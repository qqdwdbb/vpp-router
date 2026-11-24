package main

import "errors"

type AdminVPPDNSHijack struct {
	Enabled   bool `json:"enabled"`
	Available bool `json:"available"`
}

func vppDNSHijackState(entry map[string]any) AdminVPPDNSHijack {
	entries, _ := entry["hijack_vpp"].([]any)
	dns, _ := entry["hijack_dns"].(bool)
	enabled := true
	if value, ok := entry["hijack_vpp_enabled"].(bool); ok {
		enabled = value
	}
	available := dns && len(entries) > 0
	return AdminVPPDNSHijack{Enabled: available && enabled, Available: available}
}

func (a *Admin) SetVPPDNSHijack(enabled bool, user string) (*AdminState, error) {
	description := "关闭 VPP 侧 DNS 劫持"
	if enabled {
		description = "开启 VPP 侧 DNS 劫持"
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		entry, err := readJSONObject(a.opts.Config)
		if err != nil {
			return nil, err
		}
		if loaded.path == a.opts.Config {
			entry = loaded.doc
		}
		state := vppDNSHijackState(entry)
		if !state.Available {
			return nil, errors.New("尚未配置 VPP DNS 劫持的接口、来源网段或 Linux DNS 重定向")
		}
		if state.Enabled == enabled {
			return nil, errors.New("VPP 侧 DNS 劫持没有变化")
		}
		entry["hijack_vpp_enabled"] = enabled
		data, err := renderRules(entry)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{a.opts.Config: data}, nil
	})
}
