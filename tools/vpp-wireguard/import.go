package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// importConfig turns a VPP CLI file into a stored configuration. The configuration is then
// generated back and must give the file line for line: anything it cannot express would
// otherwise vanish silently. Errors name lines only, as the file holds a private key.
func importConfig(configDir, name, file, afterUp, beforeDown string, started bool) (*wgStored, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, raw := range strings.Split(string(data), "\n") {
		if line := strings.TrimSpace(raw); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	stored, err := parseVPPConfig(lines)
	if err != nil {
		return nil, err
	}
	stored.Name, stored.Enabled, stored.SkipNATOpen = name, started, true
	service := &Service{opts: Options{ConfigDir: configDir}}
	generated := service.wgUpSteps(stored)
	if len(generated) != len(lines) {
		return nil, fmt.Errorf("%s 有 %d 条命令，结构化配置只能生成 %d 条，没有导入", file, len(lines), len(generated))
	}
	for index, step := range generated {
		if step.command != lines[index] {
			return nil, fmt.Errorf("%s 第 %d 条命令和结构化配置生成的不同，没有导入", file, index+1)
		}
	}
	for path, into := range map[string]*[]string{afterUp: &stored.AfterUp, beforeDown: &stored.BeforeDown} {
		if path == "" {
			continue
		}
		text, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if *into, err = cleanCommands(string(text)); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, err
	}
	store, err := service.loadWGStore()
	if err != nil {
		return nil, err
	}
	for _, other := range store.Configs {
		if other.Name == name || other.Instance == stored.Instance {
			return nil, fmt.Errorf("%s 已经存在，没有导入", other.iface())
		}
	}
	store.Configs = append(store.Configs, stored)
	if err := service.saveWGStore(store); err != nil {
		return nil, err
	}
	return stored, nil
}

func valueAfter(fields []string, name string) (string, bool) {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == name {
			return fields[i+1], true
		}
	}
	return "", false
}

// parseVPPConfig reads the commands it understands. Others need no error here: they are not
// generated back, so the comparison refuses the file.
func parseVPPConfig(lines []string) (*wgStored, error) {
	stored := &wgStored{}
	found := false
	for index, line := range lines {
		fields := strings.Fields(line)
		bad := func(what string) (*wgStored, error) { return nil, fmt.Errorf("第 %d 条命令%s", index+1, what) }
		switch {
		case len(fields) > 3 && strings.Join(fields[:3], " ") == "wireguard create instance":
			if found {
				return bad("：一个文件只能有一个接口")
			}
			found = true
			var err error
			if stored.Instance, err = strconv.Atoi(fields[3]); err != nil || stored.Instance < 0 {
				return bad("的实例号不对")
			}
			port, _ := valueAfter(fields, "listen-port")
			if stored.ListenPort, err = strconv.Atoi(port); err != nil {
				return bad("的监听端口不对")
			}
			key, _ := valueAfter(fields, "private-key")
			if !validWireGuardKey(key) {
				return bad("的私钥格式不对")
			}
			stored.PrivateKey = key
			stored.Source, _ = valueAfter(fields, "src")
		case len(fields) == 6 && strings.Join(fields[:4], " ") == "set interface ip address":
			if _, err := netip.ParsePrefix(fields[5]); err != nil {
				return bad("的地址不对")
			}
			stored.Addresses = append(stored.Addresses, fields[5])
		case len(fields) == 6 && strings.Join(fields[:3], " ") == "set interface mtu" && fields[3] == "packet":
			mtu, err := strconv.Atoi(fields[4])
			if err != nil {
				return bad("的 MTU 不对")
			}
			stored.MTU = mtu
		case len(fields) > 3 && strings.Join(fields[:3], " ") == "wireguard peer add":
			peer := wgStoredPeer{}
			peer.PublicKey, _ = valueAfter(fields, "public-key")
			if !validWireGuardKey(peer.PublicKey) {
				return bad("的公钥格式不对")
			}
			peer.PresharedKey, _ = valueAfter(fields, "preshared-key")
			endpoint, _ := valueAfter(fields, "endpoint")
			port, _ := valueAfter(fields, "dst-port")
			keepalive, _ := valueAfter(fields, "persistent-keepalive")
			var err error
			if peer.Port, err = strconv.Atoi(port); err != nil {
				return bad("的端点端口不对")
			}
			if peer.Keepalive, err = strconv.Atoi(keepalive); err != nil {
				return bad("的 keepalive 不对")
			}
			if address, err := netip.ParseAddr(endpoint); err != nil {
				return bad("的端点不对")
			} else if !address.IsUnspecified() {
				peer.Endpoint = endpoint
			} else if peer.Port != 0 {
				return bad("的端点没有地址却有端口")
			}
			for i := 4; i+1 < len(fields); i++ {
				if fields[i] == "allowed-ip" {
					peer.AllowedIPs = append(peer.AllowedIPs, fields[i+1])
				}
			}
			stored.Peers = append(stored.Peers, peer)
		}
	}
	if !found {
		return nil, errors.New("文件里没有 wireguard create instance")
	}
	return stored, nil
}
