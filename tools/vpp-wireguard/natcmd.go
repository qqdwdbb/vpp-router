package main

import (
	"slices"
	"strings"
)

// A configuration's commands may hold NAT44 commands for its interface, written for either
// plugin: NAT44-EI's have "ei" after nat44, NAT44-ED's do not. They run in the form of the
// plugin VPP runs, so switching the plugin (vpp-system's NAT mode) needs no edit here. The
// rewriting matches vpp-system's natmode.go and multiexit.go; commands with no equivalent run
// as written and fail, and vpp-system refuses a switch while a configuration has one.
//
// Under NAT44-ED the multi-exit commands of the nat_ei_context plugin and patch 0008 are not run:
// "nat44 ei context", "output-chain" and "pool receive". ED takes the pool address bound to the
// exit itself, so in a configuration with a context the pool address loses its tenant-vrf, which
// named the context's VRF. vpp-system checks that this holds before it switches.

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

// isNATCommand is whether a command is a NAT44 command of either plugin.
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

// isEICommand is whether a NAT44 command is written for NAT44-EI.
func isEICommand(f []string) bool {
	return len(f) > 1 && f[0] == "nat44" && f[1] == "ei" ||
		len(f) > 2 && f[1] == "nat44" && f[2] == "ei" ||
		len(f) > 3 && f[2] == "nat44" && f[3] == "ei"
}

// edOnlyOptions are NAT44-ED options NAT44-EI has no equivalent for.
var edOnlyOptions = []string{"twice-nat", "self-twice-nat", "out2in-only", "exact"}

// natCommandFor is command in the form of NAT44-EI (ei) or NAT44-ED, or command itself when it
// is not a NAT44 command, is in that form already or has no equivalent there. Plugin enable
// and timeout lines are VPP's startup's, not an interface's, and stay as written.
func natCommandFor(command string, ei bool) string {
	f := strings.Fields(command)
	if !isNATCommand(f) || isEICommand(f) == ei {
		return command
	}
	if out, ok := translateNAT(f, ei); ok {
		return strings.Join(out, " ")
	}
	return command
}

func translateNAT(f []string, ei bool) ([]string, bool) {
	words := slices.Clone(f)
	if !ei {
		switch {
		case hasWords(f, "nat44", "ei", "add", "address"), hasWords(f, "nat44", "ei", "add", "interface", "address"),
			hasWords(f, "nat44", "ei", "add", "static", "mapping"), hasWords(f, "nat44", "ei", "add", "identity", "mapping"):
			return slices.Delete(words, 1, 2), true
		case len(f) > 3 && keyword(f[0], "set") && keyword(f[1], "interface") && f[2] == "nat44" && f[3] == "ei":
			return slices.Delete(words, 3, 4), true
		}
		return nil, false
	}
	for _, word := range edOnlyOptions {
		if slices.Contains(f, word) {
			return nil, false
		}
	}
	switch {
	case hasWords(f, "nat44", "add", "address"), hasWords(f, "nat44", "add", "interface", "address"),
		hasWords(f, "nat44", "add", "static", "mapping"), hasWords(f, "nat44", "add", "identity", "mapping"):
		return slices.Insert(words, 1, "ei"), true
	case len(f) > 3 && keyword(f[0], "set") && keyword(f[1], "interface") && f[2] == "nat44" && (f[3] == "in" || f[3] == "out" || f[3] == "hairpinning"):
		return slices.Insert(words, 3, "ei"), true
	}
	return nil, false
}

// isEIOnly is whether a NAT44 command is one of the multi-exit commands NAT44-ED does without.
func isEIOnly(f []string) bool {
	return hasWords(f, "nat44", "ei", "context") || hasWords(f, "nat44", "ei", "output-chain") ||
		hasWords(f, "nat44", "ei", "pool", "receive")
}

// withoutTenantVRF is an "add address" command without its tenant-vrf.
func withoutTenantVRF(f []string) []string {
	if !hasWords(f, "nat44", "ei", "add", "address") {
		return f
	}
	out := slices.Clone(f)
	if i := slices.Index(out, "tenant-vrf"); i > 0 && i+1 < len(out) {
		out = slices.Delete(out, i, i+2)
	}
	return out
}

// natStep is a command to run and its place among the configuration's commands.
type natStep struct {
	index   int
	command string
}

// natCommands is commands with their NAT44 commands in the running plugin's form, without the
// ones it does without. It asks VPP only when there is one. c gives the context, if any.
func (a *Service) natCommands(c *wgStored, commands []string) []natStep {
	hasContext := slices.ContainsFunc(c.AfterUp, func(command string) bool { return hasWords(strings.Fields(command), "nat44", "ei", "context") })
	var out []natStep
	ei, asked := false, false
	for i, command := range commands {
		f := strings.Fields(command)
		if isNATCommand(f) {
			if !asked {
				ei, asked = a.natWord() != "", true
			}
			if !ei {
				if isEIOnly(f) {
					continue
				}
				if hasContext {
					command = strings.Join(withoutTenantVRF(f), " ")
				}
			}
			command = natCommandFor(command, ei)
		}
		out = append(out, natStep{i, command})
	}
	return out
}
