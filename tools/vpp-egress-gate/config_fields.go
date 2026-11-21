package gate

import (
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
)

// A misspelled field used to be ignored, so a rule silently did less than it said. A
// device sync refuses one, which also covers a restart and the installer. Gate itself
// only warns: it has no earlier configuration to fall back on, and one obsolete field
// should not cost DNS.

// A single file may hold what a split configuration keeps in three, so one list covers them.
var knownFields = fieldSet("route_config", "domain_routes_file", "lease_file", "upstream", "listen", "hijack_dns", "hijack_interfaces", "hijack_vpp",
	"routes", "lan_prefixes", "lan_interfaces", "interval_seconds", "monitor_resync_seconds", "max_routes", "idle_seconds", "fib_audit_seconds", "vpp_socket",
	"api_socket", "vpp_service", "state_file", "state_socket", "lock_files", "exclude_prefixes", "dns_upstream_policy", "overlap_policy", "fakeip_ttl")

// device has its own error, which says what became of it.
var knownRouteFields = fieldSet("name", "owner", "exit", "interface", "via", "ipv6", "device", "fib_table", "domains", "domain_keywords", "domain_files",
	"ip_range_files", "dns", "dns_upstream", "fake_dns", "fakeip_range", "tproxy_port", "tproxy_exit", "tproxy_interface", "tproxy_address", "linux_exit", "default_route", "dhcp_gateway")

// knownExitFields comes from the type that decodes linux_exit, so the two cannot differ.
var knownExitFields = func() map[string]bool {
	fields := map[string]bool{}
	kind := reflect.TypeOf(LinuxExit{})
	for i := 0; i < kind.NumField(); i++ {
		if name, _, _ := strings.Cut(kind.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			fields[name] = true
		}
	}
	return fields
}()

func fieldSet(names ...string) map[string]bool {
	fields := make(map[string]bool, len(names))
	for _, name := range names {
		fields[name] = true
	}
	return fields
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

// fieldHint names the likely mistake: a field of another level, or a spelling.
func fieldHint(name string, known map[string]bool, others map[string]map[string]bool) string {
	levels := make([]string, 0, len(others))
	for level := range others {
		levels = append(levels, level)
	}
	sort.Strings(levels)
	for _, level := range levels {
		if others[level][name] {
			return "; it belongs in " + level
		}
	}
	best, bestDistance := "", 3
	candidates := make([]string, 0, len(known))
	for candidate := range known {
		candidates = append(candidates, candidate)
	}
	sort.Strings(candidates)
	for _, candidate := range candidates {
		if distance := editDistance(name, candidate); distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	if best != "" {
		return fmt.Sprintf("; did you mean %q?", best)
	}
	return ""
}

func unknownFieldsOf(object map[string]any, known map[string]bool, others map[string]map[string]bool, where string) []string {
	names := make([]string, 0, len(object))
	for name := range object {
		if !known[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	problems := make([]string, 0, len(names))
	for _, name := range names {
		problems = append(problems, fmt.Sprintf("%s: unknown field %q%s", where, name, fieldHint(name, known, others)))
	}
	return problems
}

// unknownFields checks one document at each of its three levels.
func unknownFields(doc map[string]any, path string) []string {
	problems := unknownFieldsOf(doc, knownFields, map[string]map[string]bool{"a rule": knownRouteFields, "linux_exit": knownExitFields}, path)
	routes, _ := doc["routes"].([]any)
	for i, item := range routes {
		route, ok := item.(map[string]any)
		if !ok {
			continue
		}
		where := fmt.Sprintf("%s: rule %d", path, i+1)
		if name, _ := route["name"].(string); name != "" {
			where = fmt.Sprintf("%s: rule %s", path, name)
		}
		problems = append(problems, unknownFieldsOf(route, knownRouteFields, map[string]map[string]bool{"linux_exit": knownExitFields, "the top level": knownFields}, where)...)
		if exit, ok := route["linux_exit"].(map[string]any); ok {
			problems = append(problems, unknownFieldsOf(exit, knownExitFields, map[string]map[string]bool{"the rule, outside linux_exit": knownRouteFields}, where+" linux_exit")...)
		}
	}
	return problems
}

// configFieldProblems reads the entry and the files it links. A file that cannot be
// read is for whoever loads it to report, and the same goes for a file named twice.
func configFieldProblems(path string) []string {
	entry, err := readJSONObject(path)
	if err != nil {
		return nil
	}
	problems := unknownFields(entry, path)
	seen := map[string]bool{path: true}
	for _, key := range []string{"route_config", "domain_routes_file"} {
		linked, _ := entry[key].(string)
		if linked == "" || seen[linked] {
			continue
		}
		seen[linked] = true
		if doc, err := readJSONObject(linked); err == nil {
			problems = append(problems, unknownFields(doc, linked)...)
		}
	}
	return problems
}

func warnUnknownFields(path string) {
	for _, problem := range configFieldProblems(path) {
		log.Printf("%s; it is ignored", problem)
	}
}

func refuseUnknownFields(path string) error {
	if problems := configFieldProblems(path); len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}
