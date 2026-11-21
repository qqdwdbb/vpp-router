package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
)

// When the LAN gateway moves within its network, what hands it out follows: dnsmasq's router
// option, and the installer's router.env (HOST_GW), which gives Linux on the management TAP
// its default route. Each step is recorded in the pending change as it is made, so that a
// rollback, even after this service restarts, undoes exactly those.

// Follow is what followed a gateway change.
type Follow struct {
	From  string `json:"from"`
	To    string `json:"to"`
	DHCP  bool   `json:"dhcp,omitempty"`  // dnsmasq's router option was changed
	Env   bool   `json:"env,omitempty"`   // router.env's HOST_GW was changed
	Route string `json:"route,omitempty"` // the Linux interface whose default route was moved
}

// gatewayChange is a gateway move an address change makes.
type gatewayChange struct{ from, to netip.Addr }

// envValues reads the KEY=value lines of router.env.
func envValues(path string) (map[string]string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	values := map[string]string{}
	for _, line := range lines {
		if key, value, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return values, lines, nil
}

// setEnv changes KEY=from into KEY=to; false when the file says something else.
func setEnv(path, key, from, to string) (bool, error) {
	values, lines, err := envValues(path)
	if err != nil || values[key] != from {
		return false, err
	}
	for i, line := range lines {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			lines[i] = key + "=" + to
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return true, writeFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), info.Mode().Perm())
}

// follow makes dnsmasq and Linux follow the pending change's gateway move.
func (s *Service) follow(move gatewayChange) error {
	f := &Follow{From: move.from.String(), To: move.to.String()}
	s.pending.Follow = f
	if err := s.dhcp.SetRouter(move.from, move.to); err != nil {
		return err
	}
	f.DHCP = true
	if s.opts.RouterEnv == "" {
		return nil
	}
	values, _, err := envValues(s.opts.RouterEnv)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if f.Env, err = setEnv(s.opts.RouterEnv, "HOST_GW", f.From, f.To); err != nil {
		return err
	}
	tap := values["HOST_TAP"]
	if f.Env && values["HOST_DEFAULT"] == "1" && tap != "" && s.linkExists(tap) {
		if err := s.run("ip", "-4", "route", "replace", "default", "via", f.To, "dev", tap); err != nil {
			return err
		}
		f.Route = tap
	}
	return nil
}

// unfollow undoes what follow did, the last step first.
func (s *Service) unfollow(f *Follow) error {
	var problems []string
	if f.Route != "" {
		if err := s.run("ip", "-4", "route", "replace", "default", "via", f.From, "dev", f.Route); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if f.Env {
		if _, err := setEnv(s.opts.RouterEnv, "HOST_GW", f.To, f.From); err != nil {
			problems = append(problems, "router.env："+err.Error())
		}
	}
	if f.DHCP && s.dhcp != nil {
		from, _ := netip.ParseAddr(f.From)
		to, _ := netip.ParseAddr(f.To)
		if err := s.dhcp.SetRouter(to, from); err != nil {
			problems = append(problems, "dnsmasq："+err.Error())
		}
	}
	if len(problems) > 0 {
		err := fmt.Errorf("网关 %s 没有完全恢复：%s", f.From, strings.Join(problems, "；"))
		log.Print(err)
		return err
	}
	return nil
}
