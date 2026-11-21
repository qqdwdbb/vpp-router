package main

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// RuleEdit is everything the panel's edit dialog sets on a rule group at once.
type RuleEdit struct {
	Exit string
	// DNS nil takes what the exit comes with; empty means the default DNS.
	DNS      *string
	Files    []string // domain lists
	Ranges   []string // address lists
	Keywords []string
}

// uniqueStrings drops repeats and empty values, keeping the order.
func uniqueStrings(values []string) []string {
	out := []string{}
	for _, value := range values {
		if value != "" && !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func baseNames(paths []string) string {
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	return strings.Join(names, "、")
}

// EditRule changes a group's exit, DNS and matches as one change, so one confirmation covers
// it. Domains written into the rule by hand are kept.
func (a *Admin) EditRule(group string, edit RuleEdit, user string) (*AdminState, error) {
	keywords, err := normalizeKeywords(edit.Keywords)
	if err != nil {
		return nil, err
	}
	var upstream []any
	if edit.DNS != nil {
		if upstream, err = parseDNS(*edit.DNS); err != nil {
			return nil, err
		}
	}
	files, ranges := uniqueStrings(edit.Files), uniqueStrings(edit.Ranges)
	description := fmt.Sprintf("修改规则 %s：出口 %s", group, edit.Exit)
	if edit.DNS != nil {
		description += "，DNS 用 " + dnsLabel(upstream)
	}
	if len(files) > 0 {
		description += "，域名表 " + baseNames(files)
	}
	if len(ranges) > 0 {
		description += "，网段表 " + baseNames(ranges)
	}
	if len(keywords) > 0 {
		description += fmt.Sprintf("，%d 个关键词", len(keywords))
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		members, err := findGroup(loaded.rules, group)
		if err != nil {
			return nil, err
		}
		before, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		profiles := a.profiles(loaded.rules)
		described := describeGroup(loaded.rules, profiles, members)
		moving := edit.Exit != described.Exit
		if moving {
			if described.Locked != "" {
				return nil, errors.New(described.Locked)
			}
			if !slices.Contains(described.Options, edit.Exit) {
				return nil, fmt.Errorf("%s 不能切换到出口 %s：这个出口带不了它", group, edit.Exit)
			}
		}
		managed, err := a.allFiles(loaded.rules)
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			if _, ok := managed[path]; !ok || listKind(path, loaded.rules) != kindDomains {
				return nil, fmt.Errorf("%s 不是已有的%s", filepath.Base(path), kindLabel[kindDomains])
			}
		}
		// Each address list goes to the rules of the families it holds: a group whose IPv4 and
		// IPv6 take separate next hops is two rules.
		rangeFamilies := make(map[string][]int, len(ranges))
		for _, path := range ranges {
			if _, ok := managed[path]; !ok || listKind(path, loaded.rules) != kindRanges {
				return nil, fmt.Errorf("%s 不是已有的%s", filepath.Base(path), kindLabel[kindRanges])
			}
			seen := map[int]bool{}
			for _, network := range rangePrefixes(map[string]any{"ip_range_files": []any{path}}, nil) {
				if network.Addr().Is4() {
					seen[4] = true
				} else {
					seen[6] = true
				}
			}
			if len(seen) == 0 {
				return nil, fmt.Errorf("%s 里没有可用的网段", filepath.Base(path))
			}
			for _, family := range []int{4, 6} {
				if seen[family] {
					rangeFamilies[path] = append(rangeFamilies[path], family)
				}
			}
		}
		used := map[string]bool{}
		for _, index := range members {
			rule := loaded.rules[index]
			if len(files) == 0 && len(ranges) == 0 && len(keywords) == 0 && len(anyStrings(rule["domains"])) == 0 {
				return nil, errors.New("规则至少需要域名表、关键词或网段表中的一项")
			}
			delete(rule, "domain_files")
			delete(rule, "ip_range_files")
			delete(rule, "domain_keywords")
			if len(files) > 0 {
				refs := make([]any, 0, len(files))
				for _, path := range files {
					refs = append(refs, a.listReference(path))
				}
				rule["domain_files"] = refs
			}
			if len(keywords) > 0 {
				rule["domain_keywords"] = keywords
			}
			families := ruleFamilies(rule)
			var mine []any
			for _, path := range ranges {
				for _, family := range rangeFamilies[path] {
					if slices.Contains(families, family) {
						mine = append(mine, path)
						used[path] = true
						break
					}
				}
			}
			if len(mine) > 0 {
				rule["ip_range_files"] = mine
			}
		}
		for _, path := range ranges {
			if !used[path] {
				return nil, fmt.Errorf("%s 的网段地址族不在规则 %s 里", filepath.Base(path), group)
			}
		}
		for _, index := range members {
			rule := loaded.rules[index]
			exit := described.Exit
			if moving {
				exit = edit.Exit
			}
			profile := exitProfile(profiles, exit, rule)
			if profile == nil {
				if moving {
					return nil, fmt.Errorf("%s 不能切换到出口 %s：这个出口带不了它", group, exit)
				}
			}
			if moving {
				for key := range rule {
					if !ruleSourceFields[key] {
						delete(rule, key)
					}
				}
				for key, value := range profile {
					rule[key] = value
				}
			}
			if edit.DNS != nil {
				if err := setRuleDNS(rule, upstream); err != nil {
					return nil, err
				}
			}
		}
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(before, data) {
			return nil, errors.New("规则没有变化")
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

// SetDefault changes the default exit and the default DNS as one change. A nil value stays.
func (a *Admin) SetDefault(exit, dns *string, user string) (*AdminState, error) {
	var upstream []any
	var parts []string
	if exit != nil {
		if *exit == "" {
			parts = append(parts, "默认路由改回系统路由表")
		} else {
			parts = append(parts, "默认路由改走出口 "+*exit)
		}
	}
	if dns != nil {
		var err error
		if upstream, err = parseDNS(*dns); err != nil {
			return nil, err
		}
		if upstream == nil {
			return nil, errors.New("默认 DNS 不能为空")
		}
		parts = append(parts, "默认 DNS 改成 "+dnsTextOf(upstream))
	}
	if len(parts) == 0 {
		return nil, errors.New("默认出口和 DNS 都没有变化")
	}
	return a.change(strings.Join(parts, "，"), user, func(loaded *adminRules) (map[string][]byte, error) {
		changed := map[string][]byte{}
		if exit != nil && *exit != loaded.defaultExit {
			if *exit != "" {
				found := false
				for _, profile := range defaultProfiles(a.allProfiles(loaded.rules)) {
					found = found || ruleExit(profile) == *exit
				}
				if !found {
					return nil, fmt.Errorf("出口 %s 不能作为默认出口：没有这个出口，或者它是 Fake-IP 出口", *exit)
				}
			}
			loaded.defaultExit = *exit
			changed[loaded.path] = nil
		}
		if dns != nil {
			entry, err := readJSONObject(a.opts.Config)
			if err != nil {
				return nil, err
			}
			if loaded.path == a.opts.Config {
				entry = loaded.doc
			}
			if current, ok := entry["upstream"].([]any); !ok || dnsTextOf(current) != dnsTextOf(upstream) {
				entry["upstream"] = upstream
				data, err := renderRules(entry)
				if err != nil {
					return nil, err
				}
				changed[a.opts.Config] = data
			}
		}
		if len(changed) == 0 {
			return nil, errors.New("默认出口和 DNS 都没有变化")
		}
		if _, ok := changed[loaded.path]; ok {
			data, err := renderRules(loaded.doc)
			if err != nil {
				return nil, err
			}
			changed[loaded.path] = data
		}
		return changed, nil
	})
}
