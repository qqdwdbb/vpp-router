package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// proxyExits gets listener settings from the same service that owns the proxy page.
func (a *Admin) proxyExits() []map[string]any {
	if a.opts.ProxySocket == "" {
		return nil
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", a.opts.ProxySocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://proxy/proxy/exits")
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	var offered []map[string]any
	if json.NewDecoder(http.MaxBytesReader(nil, response.Body, adminMaxBody)).Decode(&offered) != nil {
		return nil
	}
	// Gate routes replies to IPv6 clients only to the networks it knows: fixed ones, or those
	// it follows on lan_interfaces.
	ipv6 := false
	if config, err := readJSONObject(a.opts.Config); err == nil {
		ipv6 = len(anyStrings(config["lan_interfaces"])) > 0
		for _, text := range anyStrings(config["lan_prefixes"]) {
			if p, err := netip.ParsePrefix(text); err == nil && p.Addr().Is6() {
				ipv6 = true
			}
		}
	}
	var profiles []map[string]any
	for _, p := range offered {
		name, _ := p["tproxy_exit"].(string)
		port, err := asInt(p["tproxy_port"])
		if name != "tproxy" || err != nil || port < 1 || port > 65535 {
			continue
		}
		if !ipv6 {
			p["ipv6"] = false
			if p["fakeip_range"] != nil {
				var pools []any
				for _, pool := range anyStrings(p["fakeip_range"]) {
					if prefix, err := netip.ParsePrefix(pool); err == nil && prefix.Addr().Is4() {
						pools = append(pools, pool)
					}
				}
				if len(pools) == 0 {
					continue
				}
				p["fakeip_range"] = pools
			}
		}
		profiles = append(profiles, p)
	}
	return profiles
}
