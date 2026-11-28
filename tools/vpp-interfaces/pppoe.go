package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// PPPoE dialling, by the pppoeclient plugin (plugins/pppoeclient). One line of the file,
//
//	create pppoe client BASE host-uniq N name IF username U password P use-peer-dns add-default-route4
//
// dials on BASE, an Ethernet interface or VLAN sub-interface, and creates IF, a point-to-point
// PPPoX interface that gets the IPv4 address and default route the ISP gives. IF is an
// interface like any other from then on: it can be an exit, and have IPv6 by SLAAC or DHCPv6.
// The panel always writes a name: the plugin's own pppoxN follows the order clients are
// created in, which differs between a running VPP and the file after deletions.

// pppoeConfig is one client line.
type pppoeConfig struct {
	base, name         string
	hostUniq           uint32
	username, password string
	// rest are the line's other options, kept as written: ac-name, mtu, add-default-route6 ...
	rest []string
}

// The plugin's options: those with a value, and flags.
var (
	pppoeValueOptions = []string{"host-uniq", "name", "username", "password", "ac-name", "service-name", "mtu", "mru", "timeout"}
	pppoeFlags        = []string{"use-peer-dns", "add-default-route", "add-default-route4", "add-default-route6"}
)

// parsePPPoE reads "create pppoe client ..." split into words. A line this does not fully
// understand, a deletion included, is not one.
func parsePPPoE(f []string) (*pppoeConfig, bool) {
	if len(f) < 4 || f[3] == "sw-if-index" {
		return nil, false
	}
	c := &pppoeConfig{base: f[3]}
	hostUniq := false
	for i := 4; i < len(f); i++ {
		word := f[i]
		switch {
		case slices.Contains(pppoeFlags, word):
			c.rest = append(c.rest, word)
		case slices.Contains(pppoeValueOptions, word) && i+1 < len(f):
			value := f[i+1]
			i++
			switch word {
			case "host-uniq":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return nil, false
				}
				c.hostUniq, hostUniq = uint32(n), true
			case "name":
				c.name = value
			case "username":
				c.username = value
			case "password":
				c.password = value
			default:
				c.rest = append(c.rest, word, value)
			}
		default:
			return nil, false
		}
	}
	if c.name == "" || !hostUniq {
		return nil, false
	}
	return c, true
}

// command is the line creating the client.
func (c *pppoeConfig) command() string {
	parts := []string{"create pppoe client", c.base, "host-uniq", strconv.FormatUint(uint64(c.hostUniq), 10), "name", c.name}
	if c.username != "" {
		parts = append(parts, "username", c.username)
	}
	if c.password != "" {
		parts = append(parts, "password", c.password)
	}
	return strings.Join(append(parts, c.rest...), " ")
}

// deleteCommand removes the client and its interface, sending the access concentrator a PADT.
func (c *pppoeConfig) deleteCommand() string {
	return fmt.Sprintf("create pppoe client %s host-uniq %d del", c.base, c.hostUniq)
}

// authCommand changes the account of a running client; restartCommand redials with it.
func (c *pppoeConfig) authCommand() string {
	return "set pppoe client " + c.name + " username " + c.username + " password " + c.password
}

func pppoeRestartCommand(name string) string { return "pppoe client restart " + name }

// secretWord is a password or the like as a word of a command: the plugin reads words split at
// white space, up to 255 bytes. The file is a CLI file, so a word cannot begin a comment either.
func secretWord(text string) bool {
	return text != "" && len(text) <= 255 && !strings.ContainsFunc(text, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// redact hides the passwords in text that may be shown or logged: a line of the file, a
// command, or VPP's reply to one, which repeats the input it did not understand.
var passwordWord = regexp.MustCompile(`(\bpassword\s+)\S+`)

func redact(text string) string { return passwordWord.ReplaceAllString(text, "${1}******") }

// fileText is a line as it may be shown.
func (l *cliLine) shownText() string { return redact(strings.TrimSpace(l.text)) }

// pppoeLine is the line of the client creating iface, or nil.
func pppoeLine(file *cliFile, iface string) *cliLine {
	for _, i := range file.own(iface, linePPPoE) {
		return file.lines[i]
	}
	return nil
}

// pppoeClients are the client lines dialling on base.
func pppoeClients(file *cliFile, base string) []*pppoeConfig {
	var found []*pppoeConfig
	for _, line := range file.lines {
		if line.kind == linePPPoE && line.base == base {
			found = append(found, line.pppoe)
		}
	}
	return found
}

// pppoeAccessReason says why base cannot carry a new client, or empty.
func pppoeAccessReason(file *cliFile, live *liveState, base *liveInterface) string {
	bd, bvi := fileBridge(file, base.Name)
	switch kind := kindOf(base); {
	case base.Bridge != 0 || base.BVI || bd != 0 || bvi:
		return "接口在网桥里，二层口不能拨号，先移出网桥"
	case kind != "physical" && kind != "sub" && !strings.HasPrefix(base.Name, "host-"):
		return "只能在以太网口或 VLAN 子接口上拨号"
	case len(pppoeClients(file, base.Name)) > 0:
		return "这个接口上已经有 PPPoE 拨号"
	}
	return ""
}

// pppoeCreate is the creation of a client on q.Parent, for CreateDevice.
func pppoeCreate(file *cliFile, live *liveState, q DeviceRequest) (*pppoeConfig, error) {
	base, err := editable(file, live, strings.TrimSpace(q.Parent))
	if err != nil {
		return nil, err
	}
	if reason := pppoeAccessReason(file, live, base); reason != "" {
		return nil, fmt.Errorf("%s：%s", base.Name, reason)
	}
	if !secretWord(q.Username) || !secretWord(q.Password) {
		return nil, errors.New("账号和密码不能为空，不能含空格，最长 255 个字符")
	}
	// Host-Uniq tells this client's discovery replies from another one's on the same port.
	used := map[uint32]bool{}
	for _, line := range file.lines {
		if line.kind == linePPPoE {
			used[line.pppoe.hostUniq] = true
		}
	}
	c := &pppoeConfig{base: base.Name, username: q.Username, password: q.Password, rest: []string{"use-peer-dns", "add-default-route4"}}
	for c.hostUniq = 1; used[c.hostUniq]; c.hostUniq++ {
	}
	n := freeInstance(file, live, 0, func(n int) string { return "pppoe" + strconv.Itoa(n) })
	c.name = "pppoe" + strconv.Itoa(n)
	return c, nil
}

// PPPoERequest changes a client's account.
type PPPoERequest struct {
	Interface string `json:"interface"`
	Username  string `json:"username"`
	// Password empty keeps the one it has.
	Password string `json:"password"`
}

// SetPPPoE changes the account a client dials with, and redials.
func (s *Service) SetPPPoE(q PPPoERequest, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		name := strings.TrimSpace(q.Interface)
		if _, err := editable(file, live, name); err != nil {
			return nil, err
		}
		line := pppoeLine(file, name)
		if line == nil {
			return nil, fmt.Errorf("%s 不是配置文件里的 PPPoE 拨号接口", name)
		}
		old := *line.pppoe
		wanted := old
		wanted.rest = slices.Clone(old.rest)
		wanted.username = strings.TrimSpace(q.Username)
		if q.Password != "" {
			wanted.password = q.Password
		}
		if !secretWord(wanted.username) || !secretWord(wanted.password) {
			return nil, errors.New("账号和密码不能为空，不能含空格，最长 255 个字符")
		}
		if wanted.username == old.username && wanted.password == old.password {
			return nil, errors.New("账号和密码没有变化")
		}
		c := &change{file: file, description: fmt.Sprintf("把 %s 的 PPPoE 账号改成 %s 并重新拨号", name, wanted.username)}
		if wanted.username == old.username {
			c.description = fmt.Sprintf("修改 %s 的 PPPoE 密码并重新拨号", name)
		}
		undo := ""
		if old.username != "" && old.password != "" {
			undo = old.authCommand() + "\n" + pppoeRestartCommand(name)
		}
		c.steps = []step{{wanted.authCommand(), undo}, {pppoeRestartCommand(name), ""}}
		file.replace(file.own(name, linePPPoE)[0], wanted.command())
		return c, nil
	})
}

// PPPoEView is a client as the panel shows it; the password never leaves the service.
type PPPoEView struct {
	Access   string `json:"access"` // the interface it dials on
	Username string `json:"username"`
	Password bool   `json:"password"` // whether one is set
	// What the plugin says now; empty State when it is not running.
	State      string `json:"state"`
	Session    uint32 `json:"session"`
	ACMAC      string `json:"ac_mac"`
	Reconnects uint32 `json:"reconnects"`
	Last       string `json:"last_disconnect"`
	AuthFails  uint32 `json:"auth_failures"`
}

func pppoeView(c *pppoeConfig, live *livePPPoE) *PPPoEView {
	v := &PPPoEView{Access: c.base, Username: c.username, Password: c.password != ""}
	if live != nil {
		v.State, v.Session, v.ACMAC, v.Reconnects, v.Last, v.AuthFails = live.State, live.Session, live.ACMAC, live.Reconnects, live.Last, live.AuthFails
	}
	return v
}

// livePPPoE is what the plugin says about the client of a PPPoX interface.
type livePPPoE struct {
	State      string // discovery, request (PADR sent) or session
	Session    uint32
	ACMAC      string
	Reconnects uint32
	Last       string // the reason the last session ended: padt, echo-timeout, auth-fail ...
	AuthFails  uint32
}

// "show pppoe client":
//
//	[0] sw-if-index 1 host-uniq 1 pppox-sw-if-index 3 state PPPOE_CLIENT_SESSION session-id 1 ac-mac-address 02:00:00:00:00:01
var pppoeClientLine = regexp.MustCompile(`(?m)^\[\d+\] sw-if-index \d+ host-uniq \d+ pppox-sw-if-index (\d+) state PPPOE_CLIENT_(\w+) session-id (\d+) ac-mac-address (\S+)`)

// "show pppoe client debug IF" adds the history of the client:
//
//	reconnects 2 last-disconnect auth-fail next-discovery 12.0s
//	auth-failures 1
var (
	pppoeReconnects = regexp.MustCompile(`(?m)^\s+reconnects (\d+) last-disconnect (\S+)`)
	pppoeAuthFails  = regexp.MustCompile(`(?m)^\s+auth-failures (\d+)`)
)

// parsePPPoEClients maps PPPoX interface indexes to their clients' state.
func parsePPPoEClients(text string) map[uint32]*livePPPoE {
	found := map[uint32]*livePPPoE{}
	for _, m := range pppoeClientLine.FindAllStringSubmatch(text, -1) {
		index, _ := strconv.ParseUint(m[1], 10, 32)
		session, _ := strconv.ParseUint(m[3], 10, 32)
		c := &livePPPoE{State: strings.ToLower(m[2]), Session: uint32(session)}
		if c.State == "session" {
			c.ACMAC = m[4]
		}
		found[uint32(index)] = c
	}
	return found
}

func parsePPPoEDebug(text string, c *livePPPoE) {
	if m := pppoeReconnects.FindStringSubmatch(text); m != nil {
		n, _ := strconv.ParseUint(m[1], 10, 32)
		c.Reconnects, c.Last = uint32(n), m[2]
	}
	if m := pppoeAuthFails.FindStringSubmatch(text); m != nil {
		n, _ := strconv.ParseUint(m[1], 10, 32)
		c.AuthFails = uint32(n)
	}
	if c.Last == "none" {
		c.Last = ""
	}
}
