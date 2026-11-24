package main

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// In the CLI file VPP runs at startup only NAT44's lines are changed: the plugin enable line
// (table sizes) and the timeout line, or, when the NAT mode changes, every NAT44 command (see
// natmode.go). Everything else is kept as it is. The file is written for NAT44-EI or NAT44-ED,
// whichever plugin the startup file enables.

// keyword accepts VPP's abbreviations of a command word, such as "int" for "interface".
func keyword(word, full string) bool {
	return word == full || len(word) >= 3 && strings.HasPrefix(full, word)
}

func hasWords(fields []string, full ...string) bool {
	if len(fields) < len(full) {
		return false
	}
	for i, word := range full {
		if !keyword(fields[i], word) {
			return false
		}
	}
	return true
}

func cliFields(line string) []string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}
	return strings.Fields(trimmed)
}

func isNATEnable(f []string) bool {
	return hasWords(f, "nat44", "ei", "plugin", "enable") || hasWords(f, "nat44", "plugin", "enable")
}

func isNATTimeout(f []string) bool {
	return hasWords(f, "set", "nat44", "ei", "timeout") || hasWords(f, "set", "nat", "timeout")
}

// enableMode is the plugin an enable line is for.
func enableMode(f []string) natMode {
	if len(f) > 1 && f[1] == "ei" {
		return natEI
	}
	return natED
}

// natSize is the NAT44 table sizes, per thread except user-sessions. NAT44-ED has sessions
// only; Users and UserSessions are 0 for it.
type natSize struct {
	Sessions     uint32 `json:"sessions"`
	Users        uint32 `json:"users"`
	UserSessions uint32 `json:"user_sessions"`
}

type natTimeouts struct {
	UDP            uint32 `json:"udp"`
	TCPEstablished uint32 `json:"tcp_established"`
	TCPTransitory  uint32 `json:"tcp_transitory"`
	ICMP           uint32 `json:"icmp"`
}

// VPP's own values, for what a line leaves out.
var (
	defaultTimeouts = natTimeouts{UDP: 300, TCPEstablished: 7440, TCPTransitory: 240, ICMP: 60}
	defaultSize     = natSize{Sessions: 10240, Users: 1024, UserSessions: 0}
)

type cliFile struct {
	lines []string
}

func parseCLI(text string) *cliFile {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return &cliFile{}
	}
	return &cliFile{lines: strings.Split(text, "\n")}
}

func (f *cliFile) String() string {
	if len(f.lines) == 0 {
		return ""
	}
	return strings.Join(f.lines, "\n") + "\n"
}

func (f *cliFile) find(match func([]string) bool) []int {
	var found []int
	for i, line := range f.lines {
		if match(cliFields(line)) {
			found = append(found, i)
		}
	}
	return found
}

// natMode is the plugin the enable line is for, empty when the file does not enable NAT44.
func (f *cliFile) natMode() natMode {
	found := f.find(isNATEnable)
	if len(found) == 0 {
		return ""
	}
	return enableMode(cliFields(f.lines[found[0]]))
}

// natSize reads the enable line; ok is false when there is none.
func (f *cliFile) natSize() (natSize, bool) {
	found := f.find(isNATEnable)
	if len(found) == 0 {
		return natSize{}, false
	}
	fields := cliFields(f.lines[found[0]])
	mode := enableMode(fields)
	size := defaultSize
	start := 4
	if mode == natED {
		size, start = natSize{Sessions: defaultSize.Sessions}, 3
	}
	for i := start; i+1 < len(fields); i++ {
		n, err := strconv.ParseUint(fields[i+1], 10, 32)
		if err != nil {
			continue
		}
		switch {
		case fields[i] == "sessions":
			size.Sessions = uint32(n)
		case fields[i] == "users" && mode == natEI:
			size.Users = uint32(n)
		case fields[i] == "user-sessions" && mode == natEI:
			size.UserSessions = uint32(n)
		default:
			continue
		}
		i++
	}
	return size, true
}

func (f *cliFile) timeouts() natTimeouts {
	t := defaultTimeouts
	for _, i := range f.find(isNATTimeout) {
		fields := cliFields(f.lines[i])
		start := 4 // set nat44 ei timeout
		if fields[1] == "nat" {
			start = 3 // set nat timeout
		}
		for j := start; j < len(fields); j++ {
			if fields[j] == "reset" {
				t = defaultTimeouts
				continue
			}
			if j+1 >= len(fields) {
				break
			}
			n, err := strconv.ParseUint(fields[j+1], 10, 32)
			if err != nil {
				continue
			}
			switch fields[j] {
			case "udp":
				t.UDP = uint32(n)
			case "tcp-established":
				t.TCPEstablished = uint32(n)
			case "tcp-transitory":
				t.TCPTransitory = uint32(n)
			case "icmp":
				t.ICMP = uint32(n)
			default:
				continue
			}
			j++
		}
	}
	return t
}

var leadingSpace = regexp.MustCompile(`^\s*`)

// setNATSize rewrites the sizes on the enable line, keeping its other options: the three of
// NAT44-EI, or NAT44-ED's sessions.
func (f *cliFile) setNATSize(size natSize) bool {
	found := f.find(isNATEnable)
	if len(found) == 0 {
		return false
	}
	line := f.lines[found[0]]
	fields := cliFields(line)
	out := []string{"nat44", "ei", "plugin", "enable"}
	values := map[string]uint32{"sessions": size.Sessions, "users": size.Users, "user-sessions": size.UserSessions}
	keys := []string{"sessions", "users", "user-sessions"}
	if enableMode(fields) == natED {
		out, values, keys = []string{"nat44", "plugin", "enable"}, map[string]uint32{"sessions": size.Sessions}, []string{"sessions"}
	}
	written := map[string]bool{}
	for i := len(out); i < len(fields); i++ {
		if v, ok := values[fields[i]]; ok && i+1 < len(fields) {
			if !written[fields[i]] {
				out = append(out, fields[i], strconv.FormatUint(uint64(v), 10))
				written[fields[i]] = true
			}
			i++
			continue
		}
		out = append(out, fields[i])
	}
	for _, key := range keys {
		if !written[key] && (key != "user-sessions" || values[key] != 0) {
			out = append(out, key, strconv.FormatUint(uint64(values[key]), 10))
		}
	}
	f.lines[found[0]] = leadingSpace.FindString(line) + strings.Join(out, " ")
	return true
}

func timeoutCommand(mode natMode, t natTimeouts) string {
	prefix := "set nat44 ei timeout"
	if mode == natED {
		prefix = "set nat timeout"
	}
	return prefix + " udp " + strconv.FormatUint(uint64(t.UDP), 10) +
		" tcp-established " + strconv.FormatUint(uint64(t.TCPEstablished), 10) +
		" tcp-transitory " + strconv.FormatUint(uint64(t.TCPTransitory), 10) +
		" icmp " + strconv.FormatUint(uint64(t.ICMP), 10)
}

// setTimeouts puts all four timeouts on one line: where the first timeout line was, or after
// the enable line. Other timeout lines are removed. It fails when NAT is not enabled in the file.
func (f *cliFile) setTimeouts(t natTimeouts) bool {
	enable := f.find(isNATEnable)
	if len(enable) == 0 {
		return false
	}
	found := f.find(isNATTimeout)
	command := timeoutCommand(enableMode(cliFields(f.lines[enable[0]])), t)
	if len(found) == 0 {
		at := enable[0] + 1
		f.lines = slices.Insert(f.lines, at, leadingSpace.FindString(f.lines[enable[0]])+command)
		return true
	}
	f.lines[found[0]] = leadingSpace.FindString(f.lines[found[0]]) + command
	for k := len(found) - 1; k > 0; k-- {
		f.lines = slices.Delete(f.lines, found[k], found[k]+1)
	}
	return true
}

// cliFileFromConfig finds the startup-config or exec file in a VPP startup file.
var startupCLI = regexp.MustCompile(`(?:^|[\s{])(?:exec|startup-config)\s+([^\s}]+)`)
var startupComment = regexp.MustCompile(`(?m)#.*$`)

func cliFileFromConfig(text string) string {
	match := startupCLI.FindStringSubmatch(startupComment.ReplaceAllString(text, ""))
	if match == nil {
		return ""
	}
	return match[1]
}
