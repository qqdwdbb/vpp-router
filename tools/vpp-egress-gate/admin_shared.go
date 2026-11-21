package gate

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// gate-admin edits Gate's configuration, so it reads it with Gate's own rules rather than a
// second copy of them. This is everything it needs from this package.

// DefaultListDir is where domain and address list files are created.
const DefaultListDir = defaultListDir

// DeviceStateDir holds what Gate generates, such as gate.json.
func DeviceStateDir() string { return deviceStateDir }

func ListFiles(item map[string]any, key string) ([]string, error) { return listFiles(item, key) }
func ParsePrefixStrict(value string) (netip.Prefix, error)        { return parsePrefixStrict(value) }
func ReadJSONObject(path string) (map[string]any, error)          { return readJSONObject(path) }
func PrefixString(p netip.Prefix) string                          { return prefixString(p) }
func PrefixesOverlap(a, b netip.Prefix) bool                      { return prefixesOverlap(a, b) }
func AsInt(v any) (int, error)                                    { return asInt(v) }
func ParseHostPort(v any) (Upstream, error)                       { return parseHostPort(v) }
func CheckDomain(domain string) error                             { return checkDomain(domain) }

func SummarizeRange(first, last netip.Addr) ([]netip.Prefix, error) {
	return summarizeRange(first, last)
}

func LinkedJSON(entry map[string]any, key string) (string, map[string]any, error) {
	return linkedJSON(entry, key)
}

// GeneratedIPv6 says whether Gate gives IPv6 to the device of a Linux exit rule that does
// not set ipv6, or will when it makes the device: what its device journal holds, or else what
// it would find on the exit now. An exit can be offered with no rule on it, so with no device.
func GeneratedIPv6(rule map[string]any) bool {
	exit, ok := rule["linux_exit"].(map[string]any)
	if !ok || rule["interface"] != nil {
		return false
	}
	if _, stated := rule["ipv6"]; stated {
		return false
	}
	state, err := loadDeviceState()
	if err != nil {
		return false
	}
	lanIPv6 := len(state.LANInterfaces) > 0
	for _, lan := range state.LANs {
		if prefix, err := netip.ParsePrefix(lan); err == nil && prefix.Addr().Is6() {
			lanIPv6 = true
		}
	}
	if !lanIPv6 {
		return false
	}
	iface, _ := exit["interface"].(string)
	name, _ := rule["name"].(string)
	for _, host := range []string{deviceName(deviceExitPrefix, iface), deviceName(deviceGatewayPrefix, name)} {
		d := state.Devices[host]
		if d == nil || d.SharedTAP || d.Exit != iface {
			continue
		}
		if !d.Retired {
			return d.IPv6
		}
		// A retired device comes back with what Gate found before.
		if d.IPv6Found {
			return true
		}
	}
	gateway, _ := exit["gateway"].(string)
	gateway6, _ := exit["gateway6"].(string)
	return exitIPv6Now(iface, gateway != "", gateway6)
}

// exitIPv6Now caches what the exit has for a few seconds: the panel asks for every rule
// and exit of a page.
var exitIPv6Cache = struct {
	sync.Mutex
	entries map[string]exitIPv6Entry
}{entries: map[string]exitIPv6Entry{}}

type exitIPv6Entry struct {
	at  time.Time
	has bool
}

func exitIPv6Now(iface string, gateway bool, gateway6 string) bool {
	key := fmt.Sprint(iface, "|", gateway, "|", gateway6)
	exitIPv6Cache.Lock()
	defer exitIPv6Cache.Unlock()
	if e, ok := exitIPv6Cache.entries[key]; ok && time.Since(e.at) < 5*time.Second {
		return e.has
	}
	has := linuxExitHasIPv6(context.Background(), iface, gateway, gateway6)
	exitIPv6Cache.entries[key] = exitIPv6Entry{time.Now(), has}
	return has
}
