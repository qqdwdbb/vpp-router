package main

import (
	"errors"
	"fmt"
	"strings"
)

// An exit is an interface whose outgoing traffic NAT44 translates to the interface's own
// address, as the installer sets up its WAN. The panel turns it on and off for any interface,
// so that a second uplink needs no hand-written NAT. VPP runs NAT44-EI or NAT44-ED, whichever
// plugin its startup file enables; the commands follow that.

// natModeOf is the NAT44 plugin the file's NAT lines are written for and the one VPP runs.
// The file's lines win when VPP has no NAT plugin; it is an error when the two differ, or
// when neither says.
func natModeOf(file *cliFile, name string, live *liveState) (natMode, error) {
	var mode natMode
	for _, line := range file.lines {
		switch line.kind {
		case lineNATEnable, lineNATAddress, lineNATOutput, lineNATHairpin:
			if mode != "" && line.nat != mode {
				return "", fmt.Errorf("%s 里同时有 NAT44-EI 和 NAT44-ED 的命令", name)
			}
			mode = line.nat
		}
	}
	switch {
	case mode == "" && live.NAT == "":
		return "", errors.New("VPP 没有加载 NAT 插件（nat44_ei_plugin.so 或 nat_plugin.so）")
	case mode == "":
		return live.NAT, nil
	case live.NAT != "" && live.NAT != mode:
		return "", fmt.Errorf("%s 里是 %s 的命令，VPP 运行的却是 %s，先在系统页把 NAT 模式改一致", name, mode, live.NAT)
	}
	return mode, nil
}

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
	case len(file.own(iface.Name, lineNATHairpin)) > 0:
		return "接口开着 NAT 回流，在局域网一侧，不能做出口"
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
		mode, err := natModeOf(file, s.opts.CLIFile, live)
		if err != nil {
			return nil, err
		}
		if !enable {
			if refs := natReferences(file, name); len(refs) > 0 {
				return nil, fmt.Errorf("配置文件里还有引用 %s 的 NAT 命令，先删掉：%s", name, strings.TrimSpace(refs[0].text))
			}
			c := &change{file: file, description: "取消 " + name + " 的出口（NAT）"}
			if len(output) > 0 {
				c.steps = append(c.steps, step{natOutputCommand(mode, name, true), natOutputCommand(mode, name, false)})
			}
			if len(pool) > 0 {
				c.steps = append(c.steps, step{natAddressCommand(mode, name, true), natAddressCommand(mode, name, false)})
			}
			file.remove(append(pool, output...)...)
			return c, nil
		}
		if reason := natReason(file, live, iface); reason != "" {
			return nil, errors.New(reason)
		}
		c := &change{file: file, description: "把 " + name + " 设为出口（NAT）"}
		addExit(file, c, mode, name)
		return c, nil
	})
}

// addExit adds the lines and commands making name an exit to a change: the plugin's enable
// line if the file has none, the address pool and the output feature.
func addExit(file *cliFile, c *change, mode natMode, name string) {
	pool, output := natLines(file, name)
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
		file.insert(at, natEnableCommand(mode), natTimeoutCommand(mode))
		enableLine = at + 1
		c.steps = append(c.steps, step{natEnableCommand(mode), natDisableCommand(mode)}, step{natTimeoutCommand(mode), ""})
	}
	var texts []string
	if len(pool) == 0 {
		texts = append(texts, natAddressCommand(mode, name, false))
		c.steps = append(c.steps, step{natAddressCommand(mode, name, false), natAddressCommand(mode, name, true)})
	}
	if len(output) == 0 {
		texts = append(texts, natOutputCommand(mode, name, false))
		c.steps = append(c.steps, step{natOutputCommand(mode, name, false), natOutputCommand(mode, name, true)})
	}
	file.insert(file.insertionPoint(name, append(append([]int{enableLine}, pool...), output...)...), texts...)
}

// Hairpinning lets hosts on a LAN reach a port forward, or another NAT mapping, by the exit's
// outside address: the packet is translated as if it came from outside and sent back in, with
// the exit's address as its source. Without it such a packet leaves by the exit unchanged. It
// costs every IPv4 packet the interface receives a reassembly lookup and a check of its
// destination against the NAT addresses, roughly 75 clocks, so it is off unless turned on.

func hairpinEnabled(file *cliFile, iface string) bool {
	return len(file.own(iface, lineNATHairpin)) > 0
}

// hairpinReason says why hairpinning cannot be turned on for iface, or empty when it can.
func hairpinReason(file *cliFile, live *liveState, iface *liveInterface) string {
	bd, bvi := fileBridge(file, iface.Name)
	switch {
	case live.NAT == "":
		return "VPP 没有加载 NAT 插件"
	case !live.HairpinCLI:
		return "VPP 的 NAT 插件没有回流命令（补丁 0043/0044），重新运行安装脚本更新 VPP 后才能用"
	case len(file.find(lineNATEnable)) == 0:
		return "还没有出口，先把上行口设为出口"
	case natEnabled(file, iface.Name):
		return "出口不需要回流，在局域网一侧的接口（比如网桥的网关接口）上开"
	case (iface.Bridge != 0 && !iface.BVI) || (bd != 0 && !bvi):
		return "接口在网桥里，在网桥的网关接口上开"
	case fileFamily(file, iface.Name, false).mode == modeNone:
		return "先给接口设置 IPv4 地址"
	}
	for _, line := range natReferences(file, iface.Name) {
		if keyword(line.words[0], "set") {
			return "这个接口的 NAT 用其他方式配置：" + strings.TrimSpace(line.text)
		}
	}
	return ""
}

// SetHairpin turns hairpinning on or off for a LAN-side interface. It takes effect at once.
func (s *Service) SetHairpin(name string, enable bool, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		lines := file.own(name, lineNATHairpin)
		if enable == (len(lines) > 0) {
			return nil, errors.New("回流设置没有变化")
		}
		mode, err := natModeOf(file, s.opts.CLIFile, live)
		if err != nil {
			return nil, err
		}
		if !enable {
			c := &change{file: file, description: "关闭 " + name + " 的 NAT 回流"}
			if live.Hairpin[name] {
				c.steps = append(c.steps, step{natHairpinCommand(mode, name, true), natHairpinCommand(mode, name, false)})
			}
			file.remove(lines...)
			return c, nil
		}
		if reason := hairpinReason(file, live, iface); reason != "" {
			return nil, errors.New(reason)
		}
		c := &change{file: file, description: "开启 " + name + " 的 NAT 回流：局域网内用出口地址访问端口转发时转回局域网"}
		if !live.Hairpin[name] {
			c.steps = append(c.steps, step{natHairpinCommand(mode, name, false), natHairpinCommand(mode, name, true)})
		}
		// After the plugin is enabled and the exits are set up, as the installer writes it.
		after := file.find(lineNATEnable, lineNATAddress, lineNATOutput)
		file.insert(file.insertionPoint(name, after...), natHairpinCommand(mode, name, false))
		return c, nil
	})
}
