package gate

import (
	"fmt"
	"net"
	"net/netip"
)

// ValidateDNSConfig refuses upstreams that send a query straight back to a Gate
// listener. A different resolver on the same host and a different port is valid.
func ValidateDNSConfig(entry, routes map[string]any) error {
	var listeners []Upstream
	if raw, present := entry["listen"]; present {
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("listen must be a list of DNS endpoints")
		}
		for _, item := range items {
			listen, err := parseHostPort(item)
			if err != nil {
				return err
			}
			listeners = append(listeners, listen)
		}
	} else {
		listeners = []Upstream{{Host: "127.0.0.1", Port: 1053}}
	}
	check := func(label string, raw any) error {
		upstream, err := parseHostPort(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		address, err := netip.ParseAddr(upstream.Host)
		if err != nil {
			return fmt.Errorf("%s: DNS host must be an IP address", label)
		}
		address = address.Unmap()
		for _, listen := range listeners {
			if upstream.Port != listen.Port {
				continue
			}
			bound, err := netip.ParseAddr(listen.Host)
			if err != nil {
				return fmt.Errorf("Gate listen host must be an IP address")
			}
			bound = bound.Unmap()
			self := address == bound
			if bound.IsUnspecified() && (bound.Is6() || address.Is4()) {
				if address.IsLoopback() || address.IsUnspecified() {
					self = true
				} else {
					addresses, err := net.InterfaceAddrs()
					if err != nil {
						return fmt.Errorf("checking local DNS addresses: %w", err)
					}
					for _, item := range addresses {
						if prefix, err := netip.ParsePrefix(item.String()); err == nil && prefix.Addr().Unmap() == address {
							self = true
							break
						}
					}
				}
			}
			if self {
				return fmt.Errorf("%s：DNS %s 指向 Gate 自身的监听地址，会形成解析环路，请填写其他 DNS 或端口", label, net.JoinHostPort(upstream.Host, fmt.Sprint(upstream.Port)))
			}
		}
		return nil
	}
	if raw, present := entry["upstream"]; present {
		if err := check("默认 DNS", raw); err != nil {
			return err
		}
	}
	items, _ := routes["routes"].([]any)
	for _, item := range items {
		rule, _ := item.(map[string]any)
		name, _ := rule["name"].(string)
		for _, field := range []string{"dns_upstream", "dns", "fake_dns"} {
			if raw, present := rule[field]; present {
				if err := check("规则 "+name+" 的 "+field, raw); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
