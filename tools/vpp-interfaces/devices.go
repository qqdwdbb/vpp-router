package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// A device is what a person thinks of as one machine. Phones joining Wi-Fi with a private
// address may show up under several MACs: one per network, or a new one every so often. The
// dhcp-script records what each client says in its requests (host name, client ID, vendor
// class and the options it asks for, which differ between systems), and a new random MAC
// joins a known device only when its host name is unique on the LAN and everything else
// matches. Anything less certain is only suggested; the panel merges and splits by hand.

const (
	defaultClients = "/var/lib/vpp-interfaces/dhcp-clients.json"
	maxClients     = 4096
	maxNameRunes   = 32
)

// Client is what the dhcp-script saw of one MAC.
type Client struct {
	IP       string    `json:"ip,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	ClientID string    `json:"client_id,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Params   string    `json:"params,omitempty"` // the parameter request list, option 55
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	// Older records may have been updated by replaying or expiring a lease.
	LastConfirmed bool `json:"last_confirmed,omitempty"`
}

func (c Client) fingerprint() string { return c.Vendor + "|" + c.Params }

// withClients runs fn on the clients file under its lock, shared with the dhcp-script; fn
// returns whether it changed anything.
func withClients(path string, fn func(map[string]Client) bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	clients := map[string]Client{}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &clients); err != nil {
			log.Printf("%s: %v; starting it again", path, err)
			clients = map[string]Client{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !fn(clients) {
		return nil
	}
	if len(clients) > maxClients {
		macs := make([]string, 0, len(clients))
		for mac := range clients {
			macs = append(macs, mac)
		}
		sort.Slice(macs, func(i, j int) bool { return clients[macs[i]].Last.Before(clients[macs[j]].Last) })
		for _, mac := range macs[:len(clients)-maxClients] {
			delete(clients, mac)
		}
	}
	out, err := marshalIndent(clients)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out, 0o600)
}

func readClients(path string) (map[string]Client, error) {
	var out map[string]Client
	err := withClients(path, func(c map[string]Client) bool { out = c; return false })
	return out, err
}

// dhcpEventActions are the first arguments dnsmasq gives its dhcp-script.
var dhcpEventActions = map[string]bool{"add": true, "old": true, "del": true, "init": true,
	"tftp": true, "arp-add": true, "arp-del": true, "relay-snoop": true}

// dhcpEvent is the dhcp-script: "add|old|del MAC IP [hostname]", the rest in DNSMASQ_*
// variables. It never fails, so that dnsmasq is never held up by it.
func dhcpEvent(args []string, getenv func(string) string, now time.Time) int {
	if len(args) < 3 || (args[0] != "add" && args[0] != "old") {
		return 0
	}
	// dnsmasq also sends "old" when it replays leases on startup or reload.
	if args[0] == "old" && (getenv("DNSMASQ_DATA_MISSING") == "1" || getenv("DNSMASQ_INTERFACE") == "") {
		return 0
	}
	mac, ok := normalMAC(args[1])
	if _, isIP := ip4(args[2]); !ok || !isIP {
		return 0 // DHCPv6 gives a DUID here
	}
	path := getenv("VPP_INTERFACES_CLIENTS")
	if path == "" {
		path = defaultClients
	}
	hostname := getenv("DNSMASQ_SUPPLIED_HOSTNAME")
	if hostname == "" && len(args) > 3 {
		hostname = args[3]
	}
	err := withClients(path, func(clients map[string]Client) bool {
		c, known := clients[mac]
		if !known {
			c.First = now
		}
		c.Last = now
		c.LastConfirmed = true
		c.IP = args[2]
		for field, value := range map[*string]string{&c.Hostname: hostname, &c.ClientID: getenv("DNSMASQ_CLIENT_ID"),
			&c.Vendor: getenv("DNSMASQ_VENDOR_CLASS"), &c.Params: getenv("DNSMASQ_REQUESTED_OPTIONS")} {
			if value != "" {
				*field = value
			}
		}
		clients[mac] = c
		return true
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vpp-interfaces dhcp-script: %v\n", err)
	}
	return 0
}

// Device is one machine and its MACs.
type Device struct {
	ID      string      `json:"id"`
	Name    string      `json:"name,omitempty"`
	MACs    []DeviceMAC `json:"macs"`
	Suggest []string    `json:"suggest,omitempty"` // devices it may be the same as
	Created time.Time   `json:"created"`
}

// DeviceMAC is one MAC of a device; Auto when it joined by the rule rather than by hand.
type DeviceMAC struct {
	MAC  string `json:"mac"`
	Auto bool   `json:"auto,omitempty"`
}

type deviceStore struct {
	Next    int       `json:"next"`
	Devices []*Device `json:"devices"`
}

// DeviceView is a device as the panel shows it.
type DeviceView struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Label    string       `json:"label"` // the name, else a host name, else a MAC
	MACs     []MACView    `json:"macs"`
	Suggest  []string     `json:"suggest"`
	IPs      []string     `json:"ips"` // addresses with an active lease or a static host
	LastSeen *time.Time   `json:"last_seen,omitempty"`
	Static   []StaticHost `json:"static"`
}

// MACView is what is known of one MAC.
type MACView struct {
	MAC      string     `json:"mac"`
	Auto     bool       `json:"auto"`
	Random   bool       `json:"random"`
	Hostname string     `json:"hostname,omitempty"`
	IP       string     `json:"ip,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	Active   bool       `json:"active"`
	Vendor   string     `json:"vendor,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

func (d *DHCP) readStore() (*deviceStore, error) {
	store := &deviceStore{}
	data, err := os.ReadFile(d.opts.Devices)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("%s: %w", d.opts.Devices, err)
	}
	return store, nil
}

func (d *DHCP) writeStore(store *deviceStore) error {
	data, err := marshalIndent(store)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.opts.Devices), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(d.opts.Devices, data, 0o600)
}

func (s *deviceStore) owner(mac string) *Device {
	for _, dev := range s.Devices {
		if slices.ContainsFunc(dev.MACs, func(m DeviceMAC) bool { return m.MAC == mac }) {
			return dev
		}
	}
	return nil
}

func (s *deviceStore) find(id string) *Device {
	for _, dev := range s.Devices {
		if dev.ID == id {
			return dev
		}
	}
	return nil
}

func (s *deviceStore) add(mac string, auto bool, now time.Time) *Device {
	s.Next++
	dev := &Device{ID: fmt.Sprintf("d%d", s.Next), MACs: []DeviceMAC{{MAC: mac, Auto: auto}}, Created: now}
	s.Devices = append(s.Devices, dev)
	return dev
}

// hostnames is the host name each MAC goes by: the one it last sent, else its lease's.
func hostnames(clients map[string]Client, leases []Lease) map[string]string {
	out := map[string]string{}
	for _, l := range leases {
		if l.Hostname != "" {
			out[l.MAC] = l.Hostname
		}
	}
	for mac, c := range clients {
		if c.Hostname != "" {
			out[mac] = c.Hostname
		}
	}
	return out
}

// reconcile gives every MAC seen a device, and reports whether the store changed.
func reconcile(store *deviceStore, clients map[string]Client, leases []Lease, hosts []StaticHost, now time.Time) bool {
	names := hostnames(clients, leases)
	// Oldest first, so that the first MAC of a phone founds its device.
	var seen []string
	add := func(mac string) {
		if !slices.Contains(seen, mac) {
			seen = append(seen, mac)
		}
	}
	byFirst := make([]string, 0, len(clients))
	for mac := range clients {
		byFirst = append(byFirst, mac)
	}
	sort.Slice(byFirst, func(i, j int) bool {
		a, b := clients[byFirst[i]], clients[byFirst[j]]
		if !a.First.Equal(b.First) {
			return a.First.Before(b.First)
		}
		return byFirst[i] < byFirst[j]
	})
	for _, mac := range byFirst {
		add(mac)
	}
	for _, l := range leases {
		if l.active(now) {
			add(l.MAC)
		}
	}
	for _, h := range hosts {
		add(h.MAC)
	}
	changed := false
	for _, mac := range seen {
		if store.owner(mac) != nil {
			continue
		}
		changed = true
		c, name := clients[mac], names[mac]
		if !randomMAC(mac) || name == "" || c.Params == "" {
			store.add(mac, false, now)
			continue
		}
		var same, named []*Device
		for _, dev := range store.Devices {
			matched, hasName := false, false
			for _, m := range dev.MACs {
				if !strings.EqualFold(names[m.MAC], name) {
					continue
				}
				hasName = true
				if other, ok := clients[m.MAC]; ok && other.fingerprint() == c.fingerprint() {
					matched = true
				}
			}
			if hasName {
				named = append(named, dev)
			}
			if matched {
				same = append(same, dev)
			}
		}
		if len(same) == 1 && len(named) == 1 {
			same[0].MACs = append(same[0].MACs, DeviceMAC{MAC: mac, Auto: true})
			continue
		}
		dev := store.add(mac, false, now)
		for _, other := range same {
			dev.Suggest = append(dev.Suggest, other.ID)
		}
	}
	return changed
}

// devicesLocked brings the devices up to date and describes them; the caller holds mu.
func (d *DHCP) devicesLocked(hosts []StaticHost, leases []Lease) ([]DeviceView, error) {
	clients, err := readClients(d.opts.Clients)
	if err != nil {
		return nil, err
	}
	store, err := d.readStore()
	if err != nil {
		return nil, err
	}
	now := d.now()
	if reconcile(store, clients, leases, hosts, now) {
		if err := d.writeStore(store); err != nil {
			return nil, err
		}
	}
	names := hostnames(clients, leases)
	views := make([]DeviceView, 0, len(store.Devices))
	for _, dev := range store.Devices {
		v := DeviceView{ID: dev.ID, Name: dev.Name, Suggest: dev.Suggest, MACs: []MACView{}, IPs: []string{}, Static: []StaticHost{}}
		if v.Suggest == nil {
			v.Suggest = []string{}
		}
		for _, m := range dev.MACs {
			mv := MACView{MAC: m.MAC, Auto: m.Auto, Random: randomMAC(m.MAC), Hostname: names[m.MAC]}
			if c, ok := clients[m.MAC]; ok {
				mv.Vendor = c.Vendor
				if c.LastConfirmed && !c.Last.IsZero() {
					last := c.Last
					mv.LastSeen = &last
				}
			}
			for _, l := range leases {
				if l.MAC == m.MAC {
					mv.IP, mv.Expires, mv.Active = l.IP, l.Expires, l.active(now)
					if mv.Active && !slices.Contains(v.IPs, l.IP) {
						v.IPs = append(v.IPs, l.IP)
					}
				}
			}
			for _, h := range hosts {
				if h.MAC == m.MAC {
					v.Static = append(v.Static, h)
					if !slices.Contains(v.IPs, h.IP) {
						v.IPs = append(v.IPs, h.IP)
					}
				}
			}
			if mv.LastSeen != nil && (v.LastSeen == nil || mv.LastSeen.After(*v.LastSeen)) {
				v.LastSeen = mv.LastSeen
			}
			v.MACs = append(v.MACs, mv)
		}
		v.Label = dev.Name
		for _, mv := range v.MACs {
			if v.Label == "" && mv.Hostname != "" {
				v.Label = mv.Hostname
			}
		}
		for _, h := range v.Static {
			if v.Label == "" && h.Name != "" {
				v.Label = h.Name
			}
		}
		if v.Label == "" && len(v.MACs) > 0 {
			v.Label = v.MACs[0].MAC
		}
		views = append(views, v)
	}
	return views, nil
}

// changeDevices loads the store, lets fn change it, saves it and returns the new state.
func (d *DHCP) changeDevices(fn func(*deviceStore, []StaticHost, []Lease) error) (*DHCPState, error) {
	if d == nil {
		return nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _, hosts, leases, err := d.load()
	if err != nil {
		return nil, err
	}
	// Every MAC seen has a device before one is changed.
	if _, err := d.devicesLocked(hosts.hosts, leases); err != nil {
		return nil, err
	}
	store, err := d.readStore()
	if err != nil {
		return nil, err
	}
	if err := fn(store, hosts.hosts, leases); err != nil {
		return nil, err
	}
	if err := d.writeStore(store); err != nil {
		return nil, err
	}
	return d.stateLocked()
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxNameRunes {
		return "", fmt.Errorf("名字最多 %d 个字", maxNameRunes)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", errors.New("名字不能有控制字符")
	}
	return name, nil
}

func (d *DHCP) NameDevice(id, name, user string) (*DHCPState, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	return d.changeDevices(func(store *deviceStore, _ []StaticHost, _ []Lease) error {
		dev := store.find(id)
		if dev == nil {
			return errors.New("没有这个设备")
		}
		dev.Name = name
		log.Printf("audit: 设备 %s 命名为 %q，由 %s 修改", id, name, user)
		return nil
	})
}

// MergeDevices moves every MAC of from into into.
func (d *DHCP) MergeDevices(into, from, user string) (*DHCPState, error) {
	return d.changeDevices(func(store *deviceStore, _ []StaticHost, _ []Lease) error {
		target, source := store.find(into), store.find(from)
		if target == nil || source == nil || target == source {
			return errors.New("要合并两个不同的设备")
		}
		for _, m := range source.MACs {
			target.MACs = append(target.MACs, DeviceMAC{MAC: m.MAC})
		}
		if target.Name == "" {
			target.Name = source.Name
		}
		store.Devices = slices.DeleteFunc(store.Devices, func(dev *Device) bool { return dev == source })
		for _, dev := range store.Devices {
			dev.Suggest = slices.DeleteFunc(dev.Suggest, func(id string) bool { return id == from || id == dev.ID })
		}
		log.Printf("audit: 设备 %s 并入 %s，由 %s 修改", from, into, user)
		return nil
	})
}

// SplitMAC makes one MAC a device of its own.
func (d *DHCP) SplitMAC(mac, user string) (*DHCPState, error) {
	mac, _ = normalMAC(strings.TrimSpace(mac))
	return d.changeDevices(func(store *deviceStore, _ []StaticHost, _ []Lease) error {
		dev := store.owner(mac)
		if dev == nil {
			return errors.New("没有这个 MAC 地址")
		}
		if len(dev.MACs) == 1 {
			return errors.New("这个设备只有这一个 MAC 地址")
		}
		dev.MACs = slices.DeleteFunc(dev.MACs, func(m DeviceMAC) bool { return m.MAC == mac })
		store.add(mac, false, d.now())
		log.Printf("audit: %s 从设备 %s 拆出，由 %s 修改", mac, dev.ID, user)
		return nil
	})
}

// ForgetDevice removes a device no longer around, with what the dhcp-script saw of it.
func (d *DHCP) ForgetDevice(id, user string) (*DHCPState, error) {
	return d.changeDevices(func(store *deviceStore, hosts []StaticHost, leases []Lease) error {
		dev := store.find(id)
		if dev == nil {
			return errors.New("没有这个设备")
		}
		now := d.now()
		macs := map[string]bool{}
		for _, m := range dev.MACs {
			macs[m.MAC] = true
		}
		for _, h := range hosts {
			if macs[h.MAC] {
				return errors.New("这个设备有静态分配，先删除静态分配")
			}
		}
		for _, l := range leases {
			if macs[l.MAC] && l.active(now) {
				return errors.New("这个设备的租约还没有过期")
			}
		}
		if err := withClients(d.opts.Clients, func(clients map[string]Client) bool {
			for mac := range macs {
				delete(clients, mac)
			}
			return true
		}); err != nil {
			return err
		}
		store.Devices = slices.DeleteFunc(store.Devices, func(other *Device) bool { return other == dev })
		for _, other := range store.Devices {
			other.Suggest = slices.DeleteFunc(other.Suggest, func(s string) bool { return s == id })
		}
		log.Printf("audit: 删除设备 %s，由 %s 修改", id, user)
		return nil
	})
}

// DismissSuggestion says a device is not the one it was suggested to be.
func (d *DHCP) DismissSuggestion(id, user string) (*DHCPState, error) {
	return d.changeDevices(func(store *deviceStore, _ []StaticHost, _ []Lease) error {
		dev := store.find(id)
		if dev == nil {
			return errors.New("没有这个设备")
		}
		dev.Suggest = nil
		log.Printf("audit: 设备 %s 不再提示合并，由 %s 修改", id, user)
		return nil
	})
}
