package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// VPP runs one of two NAT44 plugins. NAT44-EI (nat44_ei_plugin.so) maps an inside address and
// port to one outside port for every destination and lets anyone send to it (full cone).
// NAT44-ED (nat_plugin.so) keeps the inside port when it can, reuses an outside port for
// different destinations and lets in only what answers a connection (port-restricted cone).
// The startup file says which one loads; the CLI file's commands must be the same plugin's.
type natMode string

const (
	natEI natMode = "ei"
	natED natMode = "ed"
)

func (m natMode) String() string {
	switch m {
	case natEI:
		return "NAT44-EI"
	case natED:
		return "NAT44-ED"
	}
	return "无 NAT"
}

func (m natMode) plugin() string {
	if m == natED {
		return "nat_plugin.so"
	}
	return "nat44_ei_plugin.so"
}

func (m natMode) other() natMode {
	if m == natED {
		return natEI
	}
	return natED
}

// Sizes a NAT44-EI enable line gets when it is made from a NAT44-ED one, which has none:
// the installer's.
const (
	eiUsers        = 4096
	eiUserSessions = 16384
)

// isNATCommand is whether a CLI line is a NAT44 command of either plugin.
func isNATCommand(f []string) bool {
	switch {
	case len(f) == 0:
		return false
	case f[0] == "nat44":
		return true
	case len(f) > 2 && keyword(f[0], "set") && keyword(f[1], "interface") && f[2] == "nat44":
		return true
	case len(f) > 1 && keyword(f[0], "set") && (f[1] == "nat44" || f[1] == "nat"):
		return true
	}
	return false
}

// edOnlyOptions are NAT44-ED options NAT44-EI has no equivalent for.
var edOnlyOptions = []string{"twice-nat", "self-twice-nat", "out2in-only", "exact"}

// translateNAT rewrites a NAT44 command from one plugin's form to the other's. ok is false
// when it has no equivalent there.
func translateNAT(f []string, to natMode) ([]string, bool) {
	words := slices.Clone(f)
	switch {
	case to == natED:
		// The EI form has "ei" after nat44: nat44 ei ..., set interface nat44 ei ..., set nat44 ei timeout.
		switch {
		case hasWords(f, "nat44", "ei", "plugin", "enable"):
			out := []string{"nat44", "plugin", "enable"}
			for i := 4; i < len(f); i++ {
				switch f[i] {
				case "sessions", "inside-vrf", "outside-vrf":
					if i+1 < len(f) {
						out = append(out, f[i], f[i+1])
						i++
					}
				case "users", "user-sessions":
					i++ // NAT44-ED has no users
				default:
					return nil, false // static-mapping-only, connection-tracking
				}
			}
			return out, true
		case hasWords(f, "nat44", "ei", "plugin", "disable"):
			return []string{"nat44", "plugin", "disable"}, true
		case hasWords(f, "set", "nat44", "ei", "timeout"):
			return append([]string{"set", "nat", "timeout"}, f[4:]...), true
		case hasWords(f, "nat44", "ei", "add", "address"), hasWords(f, "nat44", "ei", "add", "interface", "address"),
			hasWords(f, "nat44", "ei", "add", "static", "mapping"), hasWords(f, "nat44", "ei", "add", "identity", "mapping"):
			return slices.Delete(words, 1, 2), true
		case len(f) > 3 && keyword(f[0], "set") && keyword(f[1], "interface") && f[2] == "nat44" && f[3] == "ei":
			return slices.Delete(words, 3, 4), true
		}
	case to == natEI:
		for _, word := range edOnlyOptions {
			if slices.Contains(f, word) {
				return nil, false
			}
		}
		switch {
		case hasWords(f, "nat44", "plugin", "enable"):
			out := []string{"nat44", "ei", "plugin", "enable"}
			sessions := uint32(defaultSize.Sessions)
			for i := 3; i < len(f); i++ {
				switch f[i] {
				case "sessions":
					if i+1 < len(f) {
						if n, err := strconv.ParseUint(f[i+1], 10, 32); err == nil {
							sessions = uint32(n)
						}
						out = append(out, f[i], f[i+1])
						i++
					}
				case "inside-vrf", "outside-vrf":
					if i+1 < len(f) {
						out = append(out, f[i], f[i+1])
						i++
					}
				default:
					return nil, false
				}
			}
			out = append(out, "users", strconv.Itoa(eiUsers), "user-sessions", strconv.FormatUint(uint64(min(sessions, eiUserSessions)), 10))
			return out, true
		case hasWords(f, "nat44", "plugin", "disable"):
			return []string{"nat44", "ei", "plugin", "disable"}, true
		case hasWords(f, "set", "nat", "timeout"):
			return append([]string{"set", "nat44", "ei", "timeout"}, f[3:]...), true
		case hasWords(f, "nat44", "add", "address"), hasWords(f, "nat44", "add", "interface", "address"),
			hasWords(f, "nat44", "add", "static", "mapping"), hasWords(f, "nat44", "add", "identity", "mapping"):
			return slices.Insert(words, 1, "ei"), true
		case len(f) > 3 && keyword(f[0], "set") && keyword(f[1], "interface") && f[2] == "nat44" && (f[3] == "in" || f[3] == "out"):
			return slices.Insert(words, 3, "ei"), true
		}
	}
	return nil, false
}

// lineMode is the plugin a NAT44 command is written for.
func lineMode(f []string) natMode {
	switch {
	case len(f) > 1 && f[0] == "nat44" && f[1] == "ei",
		len(f) > 2 && f[1] == "nat44" && f[2] == "ei",
		len(f) > 3 && f[2] == "nat44" && f[3] == "ei":
		return natEI
	}
	return natED
}

// withNATMode is the file with every NAT44 command in the other plugin's form, or the commands
// that have none. m is the multi-exit setup, which a switch to ED changes as multiexit.go says.
func (f *cliFile) withNATMode(to natMode, m *multiExit) (*cliFile, []string) {
	out := &cliFile{}
	var problems []string
	for i := 0; i < len(f.lines); i++ {
		line := f.lines[i]
		if to == natEI {
			if restored, edLine, ok := restoredEI(line); ok {
				out.lines = append(out.lines, restored)
				if edLine != nil && i+1 < len(f.lines) && slices.Equal(cliFields(f.lines[i+1]), edLine) {
					i++
				}
				continue
			}
		}
		fields := cliFields(line)
		if !isNATCommand(fields) || lineMode(fields) == to {
			out.lines = append(out.lines, line)
			continue
		}
		var lines []string
		ok := false
		if to == natED {
			if problem := m.edProblem(fields); problem != "" {
				problems = append(problems, strings.TrimSpace(line)+"（"+problem+"）")
				out.lines = append(out.lines, line)
				continue
			}
			lines, ok = m.toED(line, fields)
		} else if translated, done := translateNAT(fields, to); done {
			lines, ok = []string{leadingSpace.FindString(line) + strings.Join(translated, " ")}, true
		}
		if !ok {
			problems = append(problems, strings.TrimSpace(line))
			out.lines = append(out.lines, line)
			continue
		}
		out.lines = append(out.lines, lines...)
	}
	return out, problems
}

// execFiles are the files the CLI file runs.
func (f *cliFile) execFiles() []string {
	var files []string
	for _, line := range f.lines {
		if fields := cliFields(line); len(fields) == 2 && fields[0] == "exec" {
			files = append(files, fields[1])
		}
	}
	return files
}

// natPlugin is one "plugin NAME { ... }" entry of the plugins section.
type natPlugin struct {
	enabled bool
	body    *item // the { ... } of the entry
	name    *item
}

func (c *startConf) pluginEntries() (map[string]natPlugin, bool) {
	entries := map[string]natPlugin{}
	s := c.section("plugins")
	if s == nil {
		return entries, false
	}
	defaultDisabled := false
	for i := 0; i+1 < len(s.body); i++ {
		if s.body[i].section || s.body[i].word.text != "plugin" {
			continue
		}
		it := &s.body[i+1]
		enabled := false
		for _, w := range it.body {
			switch w.word.text {
			case "enable":
				enabled = true
			case "disable":
				enabled = false
			}
		}
		if it.word.text == "default" {
			defaultDisabled = !enabled && len(it.body) > 0
		} else {
			entries[it.word.text] = natPlugin{enabled: enabled, body: it, name: it}
		}
		i++
	}
	return entries, defaultDisabled
}

// natMode is the NAT44 plugin the startup file loads: empty for none, an error for both.
func (c *startConf) natMode() (natMode, error) {
	entries, defaultDisabled := c.pluginEntries()
	on := func(m natMode) bool {
		e, ok := entries[m.plugin()]
		if ok {
			return e.enabled
		}
		return c.section("plugins") == nil || !defaultDisabled
	}
	switch ei, ed := on(natEI), on(natED); {
	case ei && ed:
		return "", fmt.Errorf("启动文件同时加载 %s 和 %s，只能用一个", natEI.plugin(), natED.plugin())
	case ed:
		return natED, nil
	case ei:
		return natEI, nil
	}
	return "", nil
}

// withNATMode is the startup file loading the plugin of mode instead of the other one.
func (c *startConf) withNATMode(mode natMode) (string, error) {
	s := c.section("plugins")
	if s == nil {
		return "", fmt.Errorf("启动文件里没有 plugins 段")
	}
	entries, defaultDisabled := c.pluginEntries()
	var edits []edit
	set := func(e natPlugin, enabled bool) {
		text := "{ disable }"
		if enabled {
			text = "{ enable }"
		}
		if e.body.section {
			edits = append(edits, edit{e.body.open, e.body.shut, text})
		} else {
			edits = append(edits, edit{e.name.word.end, e.name.word.end, " " + text})
		}
	}
	old, hasOld := entries[mode.other().plugin()]
	want, hasWant := entries[mode.plugin()]
	switch {
	case hasWant:
		set(want, true)
	case hasOld:
		// The new plugin's line takes the place of the old one's.
		edits = append(edits, edit{old.name.word.start, old.name.word.end, mode.plugin()})
		set(old, true)
	default:
		edits = append(edits, edit{s.shut - 1, s.shut - 1, "  plugin " + mode.plugin() + " { enable }\n"})
	}
	// The old plugin keeps its own line only when both had one; otherwise it has none left,
	// and loads unless plugins are off by default.
	switch {
	case hasOld && hasWant:
		set(old, false)
	case !defaultDisabled:
		edits = append(edits, edit{s.shut - 1, s.shut - 1, "  plugin " + mode.other().plugin() + " { disable }\n"})
	}
	return applyEdits(c.text, edits), nil
}
