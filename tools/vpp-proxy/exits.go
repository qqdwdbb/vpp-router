package main

import (
	"net/netip"
	"path/filepath"
)

// Exits exposes only the listener settings Gate needs, from the entry managed here.
// Upstream credentials and subscription contents never cross this interface.
func (s *Service) Exits() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var entry struct {
		Inbounds []struct {
			Tag, Type, Listen string
			Port              int `json:"listen_port"`
		} `json:"inbounds"`
		DNS struct {
			Servers []struct {
				Type string
				IPv4 string `json:"inet4_range"`
				IPv6 string `json:"inet6_range"`
			} `json:"servers"`
		} `json:"dns"`
	}
	out := []map[string]any{}
	if readJSON(filepath.Join(s.opts.SingBoxDir, entryFile), &entry) != nil {
		return out
	}
	var dns []any
	for _, in := range entry.Inbounds {
		if in.Tag == "fake-dns" && in.Type == "direct" && in.Port > 0 && in.Port <= 65535 {
			addr, err := netip.ParseAddr(in.Listen)
			if err == nil {
				if addr.IsUnspecified() {
					if addr.Is4() {
						addr = netip.MustParseAddr("127.0.0.1")
					} else {
						addr = netip.IPv6Loopback()
					}
				}
				dns = []any{addr.String(), in.Port}
			}
		}
	}
	var pools []any
	for _, server := range entry.DNS.Servers {
		if server.Type != "fakeip" {
			continue
		}
		for _, pool := range []string{server.IPv4, server.IPv6} {
			if prefix, err := netip.ParsePrefix(pool); err == nil && prefix == prefix.Masked() && prefix.Bits() > 0 {
				pools = append(pools, pool)
			}
		}
	}
	for _, in := range entry.Inbounds {
		if in.Type != "tproxy" || in.Port < 1 || in.Port > 65535 || in.Tag != tproxyInbound {
			continue
		}
		addr, err := netip.ParseAddr(in.Listen)
		if err != nil {
			continue
		}
		p := map[string]any{"tproxy_exit": in.Tag, "tproxy_port": in.Port, "ipv6": addr.Is6()}
		if !addr.IsUnspecified() {
			p["tproxy_address"] = addr.String()
		}
		// The Fake-IP DNS this listener restores: rules that choose it get the pool, the rest
		// send real addresses to the same port.
		if len(pools) > 0 && dns != nil {
			p["fakeip_range"], p["dns_upstream"] = pools, dns
		}
		out = append(out, p)
	}
	return out
}
