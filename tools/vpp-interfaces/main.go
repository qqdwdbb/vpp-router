package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// vpp-interfaces makes the management panel's changes to VPP's interfaces: addresses,
// VLAN sub-interfaces, bridge domains, state and MTU. It edits the CLI file VPP runs at
// startup and applies the same change live, then undoes both unless the change is confirmed
// in time, as a wrong address can cut the network off.
func main() {
	// dnsmasq runs this program as its dhcp-script, with the event as the first argument.
	if len(os.Args) > 1 && dhcpEventActions[os.Args[1]] {
		os.Exit(dhcpEvent(os.Args[1:], os.Getenv, time.Now()))
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

const maxBody = 64 << 10

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".vpp-interfaces-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// Handler serves the API. Whoever can reach the socket is trusted, as it is root-only.
func (s *Service) Handler() http.Handler {
	reply := func(w http.ResponseWriter, value any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(value)
	}
	decode := func(w http.ResponseWriter, r *http.Request, into any) bool {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(into); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
			return false
		}
		return true
	}
	user := func(r *http.Request) string {
		if name := r.Header.Get("X-Panel-User"); name != "" {
			return name
		}
		return "unknown"
	}
	type request struct {
		Interface string   `json:"interface"`
		Addresses []string `json:"addresses"`
		Bridge    uint32   `json:"bridge"`
		BVI       bool     `json:"bvi"`
		Up        bool     `json:"up"`
		MTU       uint32   `json:"mtu"`
		Parent    string   `json:"parent"`
		SubID     uint32   `json:"sub_id"`
		VLAN      uint16   `json:"vlan"`
		Mode      string   `json:"mode"`
		Gateway   string   `json:"gateway"`
		Hostname  string   `json:"hostname"`
		NAT       bool     `json:"nat"`
		DeviceRequest
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /interfaces", func(w http.ResponseWriter, r *http.Request) {
		reply(w, s.State(), nil)
	})
	actions := map[string]func(request, string) (*State, error){
		"address": func(q request, u string) (*State, error) { return s.SetAddresses(q.Interface, q.Addresses, u) },
		"bridge":  func(q request, u string) (*State, error) { return s.SetBridge(q.Interface, q.Bridge, q.BVI, u) },
		"ipv4": func(q request, u string) (*State, error) {
			return s.SetFamily(q.Interface, false, Family{Mode: q.Mode, Addresses: q.Addresses, Gateway: q.Gateway, Hostname: q.Hostname}, u)
		},
		"ipv6": func(q request, u string) (*State, error) {
			return s.SetFamily(q.Interface, true, Family{Mode: q.Mode, Addresses: q.Addresses, Gateway: q.Gateway, Hostname: q.Hostname}, u)
		},
		"state":         func(q request, u string) (*State, error) { return s.SetState(q.Interface, q.Up, u) },
		"nat":           func(q request, u string) (*State, error) { return s.SetNAT(q.Interface, q.NAT, u) },
		"create":        func(q request, u string) (*State, error) { return s.CreateDevice(q.DeviceRequest, u) },
		"delete":        func(q request, u string) (*State, error) { return s.DeleteDevice(q.Interface, u) },
		"mtu":           func(q request, u string) (*State, error) { return s.SetMTU(q.Interface, q.MTU, u) },
		"subif":         func(q request, u string) (*State, error) { return s.CreateSubif(q.Parent, q.SubID, q.VLAN, u) },
		"subif/delete":  func(q request, u string) (*State, error) { return s.DeleteSubif(q.Interface, u) },
		"vlan":          func(q request, u string) (*State, error) { return s.ChangeVLAN(q.Interface, q.VLAN, u) },
		"bridge-domain": func(q request, u string) (*State, error) { return s.CreateBridge(q.Bridge, q.BVI, q.Addresses, u) },
		"confirm":       func(_ request, u string) (*State, error) { return s.Confirm(u) },
		"rollback":      func(_ request, u string) (*State, error) { return s.Rollback(u) },
	}
	for path, action := range actions {
		mux.HandleFunc("POST /interfaces/"+path, func(w http.ResponseWriter, r *http.Request) {
			var q request
			if decode(w, r, &q) {
				state, err := action(q, user(r))
				reply(w, state, err)
			}
		})
	}
	type dhcpRequest struct {
		DHCPRange
		StaticHost
		ID   string `json:"id"`
		From string `json:"from"`
	}
	errMeterOff := errors.New("没有启用 LAN 的 DHCP，不能按设备统计流量")
	mux.HandleFunc("GET /interfaces/meter", func(w http.ResponseWriter, r *http.Request) {
		if s.meter == nil {
			reply(w, nil, errMeterOff)
			return
		}
		reply(w, s.meter.Status(), nil)
	})
	mux.HandleFunc("POST /interfaces/meter", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Enable bool `json:"enable"`
		}
		if !decode(w, r, &q) {
			return
		}
		if s.meter == nil {
			reply(w, nil, errMeterOff)
			return
		}
		status, err := s.meter.Set(q.Enable, user(r))
		reply(w, status, err)
	})
	mux.HandleFunc("GET /interfaces/dhcp", func(w http.ResponseWriter, r *http.Request) {
		state, err := s.dhcp.State()
		reply(w, state, err)
	})
	dhcpActions := map[string]func(dhcpRequest, string) (*DHCPState, error){
		"range":          func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.SetRange(q.DHCPRange, u) },
		"host":           func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.SetHost(q.StaticHost, u) },
		"host/delete":    func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.DeleteHost(q.MAC, u) },
		"device/name":    func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.NameDevice(q.ID, q.Name, u) },
		"device/merge":   func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.MergeDevices(q.ID, q.From, u) },
		"device/split":   func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.SplitMAC(q.MAC, u) },
		"device/forget":  func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.ForgetDevice(q.ID, u) },
		"device/dismiss": func(q dhcpRequest, u string) (*DHCPState, error) { return s.dhcp.DismissSuggestion(q.ID, u) },
	}
	for path, action := range dhcpActions {
		mux.HandleFunc("POST /interfaces/dhcp/"+path, func(w http.ResponseWriter, r *http.Request) {
			var q dhcpRequest
			if decode(w, r, &q) {
				state, err := action(q, user(r))
				if err == nil {
					s.meter.Kick() // the addresses to count may have changed
				}
				reply(w, state, err)
			}
		})
	}
	return mux
}

func run(args []string) error {
	fs := flag.NewFlagSet("vpp-interfaces", flag.ContinueOnError)
	opts := Options{}
	socket := fs.String("socket", "/run/vpp-interfaces/interfaces.sock", "socket for the management panel")
	fs.StringVar(&opts.CLIFile, "cli-file", "", "the CLI file VPP runs at startup; found in -vpp-config when empty")
	vppConfig := fs.String("vpp-config", "/etc/vpp/router.conf", "VPP's startup file, read only to find -cli-file")
	fs.StringVar(&opts.VPPUnit, "vpp-unit", "", "systemd unit running VPP, restarted for changes that cannot be made live; without it they are refused")
	apiSocket := fs.String("api-socket", "/run/vpp/api.sock", "VPP API socket")
	fs.StringVar(&opts.StateDir, "state-dir", "/var/lib/vpp-interfaces", "the change waiting for confirmation and its backup")
	fs.DurationVar(&opts.Confirm, "confirm", time.Minute, "time to confirm a change before it is undone")
	fs.StringVar(&opts.ExitsFile, "exits-file", "/run/vpp-interfaces/exits.json", "where interfaces with a gateway or DHCP are published as exits, for gate-admin; empty publishes nothing")
	fs.StringVar(&opts.OtherPending, "system-pending", "/var/lib/vpp-system/pending.json", "vpp-system's pending change; no change starts while it exists. Empty to ignore")
	fs.StringVar(&opts.DHCP.Conf, "dnsmasq-conf", "", "the LAN dnsmasq's configuration, for the DHCP range, static hosts and devices; empty leaves DHCP out")
	fs.StringVar(&opts.DHCP.Unit, "dnsmasq-unit", "vpp-router-dnsmasq.service", "the LAN dnsmasq's unit")
	fs.StringVar(&opts.DHCP.Clients, "dhcp-clients", defaultClients, "what the dhcp-script records of each client; the script itself uses $VPP_INTERFACES_CLIENTS or this default")
	devices := fs.String("devices", "", "device names and their MACs; default devices.json in -state-dir")
	meterState := fs.String("meter-state", "", "whether per-device traffic counting is on; default meter.json in -state-dir")
	fs.StringVar(&opts.Meter.Published, "meter-file", "/run/vpp-interfaces/meter.json", "the counting rules, published for vpp-monitor")
	fs.StringVar(&opts.RouterEnv, "router-env", "/etc/vpp/router.env", "the installer's router.env: its HOST_GW, Linux's gateway on the management TAP, follows the LAN gateway. Empty leaves it alone")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	opts.DHCP.Devices = *devices
	if opts.DHCP.Devices == "" {
		opts.DHCP.Devices = filepath.Join(opts.StateDir, "devices.json")
	}
	opts.Meter.State = *meterState
	if opts.Meter.State == "" {
		opts.Meter.State = filepath.Join(opts.StateDir, "meter.json")
	}
	if opts.CLIFile == "" {
		data, err := os.ReadFile(*vppConfig)
		if err != nil {
			return fmt.Errorf("finding the CLI file: %w; or give -cli-file", err)
		}
		if opts.CLIFile = cliFileFromConfig(string(data)); opts.CLIFile == "" {
			return fmt.Errorf("%s has no startup-config or exec; give -cli-file", *vppConfig)
		}
	}
	if _, err := os.Stat(opts.CLIFile); err != nil {
		return err
	}
	if opts.Confirm < 10*time.Second {
		return errors.New("-confirm must be at least 10s")
	}
	vpp := &realSystem{apiSocket: *apiSocket}
	service, err := NewService(opts, vpp)
	if err != nil {
		return err
	}
	if service.dhcp != nil {
		if service.meter, err = NewMeter(opts.Meter, vpp, service.dhcp, vpp.read); err != nil {
			return err
		}
		go service.meter.Run()
	}
	if err := os.MkdirAll(filepath.Dir(*socket), 0o700); err != nil {
		return err
	}
	os.Remove(*socket)
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		return err
	}
	service.publishExits()
	log.Printf("listening on %s, editing %s", *socket, opts.CLIFile)
	// A change can wait 90 seconds for VPP to restart.
	return (&http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
