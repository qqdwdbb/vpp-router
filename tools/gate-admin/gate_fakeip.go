package main

import "fmt"

// A TPROXY listener takes real addresses and Fake-IP addresses alike; the proxy behind it turns
// Fake-IP addresses back into names. So Fake-IP is not a kind of exit but a choice of DNS: a
// rule whose DNS is the Fake-IP DNS its exit offers gets that DNS's pool, and Gate routes the
// pool there; with any other DNS the rule learns real addresses and sends them to the same port.

// fakeIPOffer is the Fake-IP DNS an exit offers and the pool that DNS hands out.
type fakeIPOffer struct {
	dns   []any
	pools any
}

// ruleDNS is the DNS a rule or profile names, if any.
func ruleDNS(rule map[string]any) []any {
	for _, key := range ruleDNSFields {
		if value, ok := rule[key].([]any); ok {
			return value
		}
	}
	return nil
}

func sameDNS(a, b []any) bool {
	return a != nil && b != nil && dnsTextOf(a) != "" && dnsTextOf(a) == dnsTextOf(b)
}

// fakeIPOffers says which exits offer a Fake-IP DNS: the proxy's listener, TPROXY exits set by
// hand, and exits seen before. The rules themselves are not asked: a rule whose DNS was just
// changed would offer its new DNS as Fake-IP.
func (a *Admin) fakeIPOffers(custom []customExit) map[string]fakeIPOffer {
	offers := map[string]fakeIPOffer{}
	add := func(profile map[string]any) {
		name := ruleExit(profile)
		if _, seen := offers[name]; seen || name == "" || profile["fakeip_range"] == nil {
			return
		}
		if dns := ruleDNS(profile); dns != nil {
			offers[name] = fakeIPOffer{dns: dns, pools: profile["fakeip_range"]}
		}
	}
	for _, profile := range a.proxyExits() {
		add(profile)
	}
	set := map[string]bool{}
	for _, exit := range custom {
		set[exit.key()] = true
		add(exit.profile())
	}
	for _, profile := range a.known {
		if !set[ruleExit(profile)] {
			add(profile)
		}
	}
	return offers
}

// applyFakeIP gives each rule the pool of its exit's Fake-IP DNS when that is the DNS it uses,
// and takes it away otherwise. A Fake-IP DNS on an exit that does not offer it would hand out
// addresses nothing there turns back into names, so it is refused.
func applyFakeIP(rules []map[string]any, offers map[string]fakeIPOffer) error {
	for _, rule := range rules {
		exit := ruleExit(rule)
		dns := ruleDNS(rule)
		for _, key := range ruleDNSFields {
			delete(rule, key)
		}
		delete(rule, "fakeip_range")
		if dns == nil {
			continue
		}
		rule["dns_upstream"] = dns
		if offer, ok := offers[exit]; ok && sameDNS(dns, offer.dns) {
			rule["fakeip_range"] = offer.pools
			continue
		}
		for other, offer := range offers {
			if sameDNS(dns, offer.dns) {
				return fmt.Errorf("规则 %s 的 DNS %s 是出口 %s 的 Fake-IP DNS，只能和出口 %s 一起用", ruleName(rule), dnsTextOf(dns), other, other)
			}
		}
	}
	return nil
}
