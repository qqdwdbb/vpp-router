package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

func normalizeKeywords(values []string) ([]string, error) {
	keywords := []string{}
	for _, value := range values {
		keyword := strings.ToLower(strings.TrimSpace(value))
		if keyword == "" {
			continue
		}
		if strings.ContainsAny(keyword, " \t\r\n") {
			return nil, fmt.Errorf("关键词 %q 不能包含空白字符", value)
		}
		if !slices.Contains(keywords, keyword) {
			keywords = append(keywords, keyword)
		}
	}
	return keywords, nil
}

// SetKeywords changes both families of a group together, preserving its other matches.
func (a *Admin) SetKeywords(group string, values []string, user string) (*AdminState, error) {
	keywords, err := normalizeKeywords(values)
	if err != nil {
		return nil, err
	}
	return a.change("修改规则 "+group+" 的关键词", user, func(loaded *adminRules) (map[string][]byte, error) {
		members, err := findGroup(loaded.rules, group)
		if err != nil {
			return nil, err
		}
		changed := false
		for _, index := range members {
			rule := loaded.rules[index]
			if len(keywords) == 0 && len(anyStrings(rule["domains"])) == 0 && len(anyStrings(rule["domain_files"])) == 0 && len(anyStrings(rule["ip_range_files"])) == 0 {
				return nil, errors.New("规则至少需要域名、关键词或网段，不能删除最后的匹配条件")
			}
			changed = changed || !slices.Equal(anyStrings(rule["domain_keywords"]), keywords)
			delete(rule, "domain_keywords")
			if len(keywords) > 0 {
				rule["domain_keywords"] = keywords
			}
		}
		if !changed {
			return nil, errors.New("关键词没有变化")
		}
		data, err := renderRules(loaded.doc)
		return map[string][]byte{loaded.path: data}, err
	})
}
