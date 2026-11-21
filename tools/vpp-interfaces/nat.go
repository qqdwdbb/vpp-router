package main

import (
	"errors"
	"fmt"
	"strings"
)

// An exit is an interface whose outgoing traffic NAT44-EI translates to the interface's own
// address, as the installer sets up its WAN. The panel turns it on and off for any interface,
// so that a second uplink needs no hand-written NAT.

// natLines returns the file's NAT lines for iface: the pool from its address, and the output
// feature.
func natLines(file *cliFile, iface string) (pool, output []int) {
	return file.own(iface, lineNATAddress), file.own(iface, lineNATOutput)
}

func natEnabled(file *cliFile, iface string) bool {
	pool, output := natLines(file, iface)
	return len(pool) > 0 && len(output) > 0
}

// natReferences are the other NAT commands naming iface: static and identity mappings on its
// address, or NAT set up as inside and outside instead of as an output feature.
func natReferences(file *cliFile, iface string) []*cliLine {
	var found []*cliLine
	for _, line := range file.references(iface) {
		if len(line.words) > 0 && (line.words[0] == "nat44" || len(line.words) > 2 && keyword(line.words[0], "set") && keyword(line.words[1], "interface") && line.words[2] == "nat44") {
			found = append(found, line)
		}
	}
	return found
}

// natReason says why NAT cannot be turned on, or empty when it can.
func natReason(file *cliFile, live *liveState, iface *liveInterface) string {
	bd, bvi := fileBridge(file, iface.Name)
	switch {
	case kindOf(iface) == "loopback" || iface.BVI || bvi:
		return "loopback 和网桥的网关接口在局域网一侧，不能做出口"
	case iface.Bridge != 0 || bd != 0:
		return "接口在网桥里，二层接口不能做出口"
	case fileFamily(file, iface.Name, false).mode == modeNone:
		return "先给接口设置 IPv4 地址或 DHCP"
	}
	for _, line := range natReferences(file, iface.Name) {
		if keyword(line.words[0], "set") {
			return "这个接口的 NAT 用其他方式配置：" + strings.TrimSpace(line.text)
		}
	}
	return ""
}

// SetNAT makes an interface an exit, translating what leaves by it, or stops that.
func (s *Service) SetNAT(name string, enable bool, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		pool, output := natLines(file, name)
		if enable == natEnabled(file, name) && (enable || len(pool)+len(output) == 0) {
			return nil, errors.New("出口设置没有变化")
		}
		if !enable {
			if refs := natReferences(file, name); len(refs) > 0 {
				return nil, fmt.Errorf("配置文件里还有引用 %s 的 NAT 命令，先删掉：%s", name, strings.TrimSpace(refs[0].text))
			}
			c := &change{file: file, description: "取消 " + name + " 的出口（NAT）"}
			if len(output) > 0 {
				c.steps = append(c.steps, step{natOutputCommand(name, true), natOutputCommand(name, false)})
			}
			if len(pool) > 0 {
				c.steps = append(c.steps, step{natAddressCommand(name, true), natAddressCommand(name, false)})
			}
			file.remove(append(pool, output...)...)
			return c, nil
		}
		if reason := natReason(file, live, iface); reason != "" {
			return nil, errors.New(reason)
		}
		c := &change{file: file, description: "把 " + name + " 设为出口（NAT）"}
		enableLine := -1
		for i, line := range file.lines {
			if line.kind == lineNATEnable {
				enableLine = i
				break
			}
		}
		if enableLine < 0 {
			// The file is what VPP ran, so without the line the plugin is off.
			at := file.insertionPoint(name)
			file.insert(at, natEnableCommand, natTimeoutCommand)
			enableLine = at + 1
			c.steps = append(c.steps, step{natEnableCommand, "nat44 ei plugin disable"}, step{natTimeoutCommand, ""})
		}
		var texts []string
		if len(pool) == 0 {
			texts = append(texts, natAddressCommand(name, false))
			c.steps = append(c.steps, step{natAddressCommand(name, false), natAddressCommand(name, true)})
		}
		if len(output) == 0 {
			texts = append(texts, natOutputCommand(name, false))
			c.steps = append(c.steps, step{natOutputCommand(name, false), natOutputCommand(name, true)})
		}
		file.insert(file.insertionPoint(name, append(append([]int{enableLine}, pool...), output...)...), texts...)
		return c, nil
	})
}
