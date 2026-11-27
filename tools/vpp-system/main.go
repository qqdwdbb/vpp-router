// vpp-system changes a VPP router's system settings for the management panel: VPP's thread
// layout and the DPDK devices' receive queues (startup file, restart and confirm), each
// interface's receive mode and the thread polling each queue (put back after VPP starts),
// NAT44-EI's timeouts and table size (startup CLI file), and the CPUs' cpufreq governors.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxBody = 1 << 16

func main() {
	if len(os.Args) > 1 && os.Args[1] == "frequency-guard" {
		if err := runFrequencyGuard(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "nat-mode" {
		if err := runNATMode(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// Handler serves the API. Whoever can reach the socket is trusted, as it is root-only.
func (s *Service) Handler(maint *Maint) http.Handler {
	reply := func(w http.ResponseWriter, value any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(value)
	}
	user := func(r *http.Request) string {
		if name := r.Header.Get("X-Panel-User"); name != "" {
			return name
		}
		return "unknown"
	}
	type request struct {
		natTimeouts
		natSize
		ThreadsRequest
		Interface string `json:"interface"`
		Mode      string `json:"mode"`
		Queue     uint32 `json:"queue"`
		Thread    *int   `json:"thread"`
		Policy    string `json:"policy"`
		Governor  string `json:"governor"`
		MinKHz    int    `json:"min_khz"`
		AddNICRequest
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /system", func(w http.ResponseWriter, r *http.Request) {
		reply(w, s.State(), nil)
	})
	actions := map[string]func(request, string) (*State, error){
		"nat/timeouts": func(q request, u string) (*State, error) { return s.SetNATTimeouts(q.natTimeouts, u) },
		"nat/size":     func(q request, u string) (*State, error) { return s.SetNATSize(q.natSize, u) },
		"nat/mode":     func(q request, u string) (*State, error) { return s.SetNATMode(natMode(q.Mode), u) },
		"threads":      func(q request, u string) (*State, error) { return s.SetThreads(q.ThreadsRequest, u) },
		"rx-mode":      func(q request, u string) (*State, error) { return s.SetRxMode(q.Interface, q.Mode, u) },
		"rx-placement": func(q request, u string) (*State, error) {
			if q.Thread == nil {
				return nil, errors.New("没有指定线程")
			}
			return s.SetRxPlacement(q.Interface, q.Queue, *q.Thread, u)
		},
		"governor":        func(q request, u string) (*State, error) { return s.SetGovernor(q.Policy, q.Governor, u) },
		"frequency-floor": func(q request, u string) (*State, error) { return s.SetFrequencyFloor(q.Policy, q.MinKHz, u) },
		"nics/add":        func(q request, u string) (*State, error) { return s.AddNIC(q.AddNICRequest, u) },
		"nics/retire":     func(q request, u string) (*State, error) { return s.RetireNIC(q.AddNICRequest.Name, u) },
		"confirm":         func(_ request, u string) (*State, error) { return s.Confirm(u) },
		"rollback":        func(_ request, u string) (*State, error) { return s.Rollback(u) },
	}
	for path, action := range actions {
		mux.HandleFunc("POST /system/"+path, func(w http.ResponseWriter, r *http.Request) {
			var q request
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&q); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
				return
			}
			state, err := action(q, user(r))
			reply(w, state, err)
		})
	}
	if maint != nil {
		maint.routes(mux, reply, user)
	}
	return mux
}

func splitList(text string) []string {
	var list []string
	for _, item := range strings.Split(text, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func run(args []string) error {
	fs := flag.NewFlagSet("vpp-system", flag.ContinueOnError)
	opts := Options{}
	socket := fs.String("socket", "/run/vpp-system/system.sock", "socket for the management panel")
	fs.StringVar(&opts.StartConf, "vpp-config", "/etc/vpp/router.conf", "VPP's startup file: its cpu section and dpdk devices are changed")
	fs.StringVar(&opts.CLIFile, "cli-file", "", "the CLI file VPP runs at startup, for NAT44-EI; found in -vpp-config when empty")
	fs.StringVar(&opts.ConfigFile, "config", "/etc/vpp/system.json", "RX modes, RX placement and governors")
	fs.StringVar(&opts.APISocket, "api-socket", "/run/vpp/api.sock", "VPP API socket")
	fs.StringVar(&opts.VPPUnit, "vpp-unit", "", "systemd unit running VPP: restarted for thread and table changes, and RX settings are put back once it is active. Without it those changes are refused, and RX settings wait 30 seconds after VPP's socket appears")
	fs.StringVar(&opts.StateDir, "state-dir", "/var/lib/vpp-system", "the change waiting for confirmation and its backups")
	fs.DurationVar(&opts.Confirm, "confirm", time.Minute, "time to confirm a change before it is undone")
	fs.IntVar(&opts.MaxWorkers, "max-workers", -1, "most workers the platform can run; -1 for no limit")
	fs.StringVar(&opts.OtherPending, "interfaces-pending", "/var/lib/vpp-interfaces/pending.json", "vpp-interfaces' pending change; no change starts while it exists. Empty to ignore")
	fs.StringVar(&opts.WireGuardStore, "wireguard-store", "/etc/vpp/wireguard/wireguard.json", "vpp-wireguard's configurations, whose commands a NAT mode switch checks. Empty to ignore")
	fs.StringVar(&opts.Sysfs, "sysfs", "/sys", "where sysfs is mounted")
	fs.StringVar(&opts.RouterEnv, "router-env", "/etc/vpp/router.env", "the installer's router.env: cards added go into its NICS. Empty turns adding cards off")
	fs.StringVar(&opts.CPUAffinityFile, "cpu-affinity-file", "/etc/systemd/system.conf.d/90-vpp-router-cpu.conf", "installer-managed systemd default CPU affinity, synchronized with worker changes")
	fs.StringVar(&opts.NICsOrig, "nics-orig", "/var/lib/vpp-router/nics.orig", "where the installer notes each card's first driver. Empty to leave it")
	fs.StringVar(&opts.PCIIDs, "pci-ids", "/usr/local/share/vpp-router/dpdk-pci-ids", "DPDK's PCI ID table from the build, which says what the PMDs drive")
	fs.StringVar(&opts.DPDKPlugin, "dpdk-plugin", "", "VPP's dpdk_plugin.so, to see if it names each port of a multi-port device; found from the startup file's plugin path when empty")
	unitDir := fs.String("unit-dir", "/etc/systemd/system", "where -vpp-unit's file is, read to see if the platform prepares RTL8125 cards; the maintenance page lists the services installed there")
	units := fs.String("units", "", "comma-separated units the maintenance page lists besides those in -unit-dir")
	backup := fs.String("backup", "/etc/vpp,/var/lib/vpp-interfaces/devices.json,/var/lib/vpp-router/nics.orig", "comma-separated files and directories in the configuration download, besides the router's unit files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	if opts.CLIFile == "" {
		data, err := os.ReadFile(opts.StartConf)
		if err != nil {
			return fmt.Errorf("finding the CLI file: %w; or give -cli-file", err)
		}
		if opts.CLIFile = cliFileFromConfig(string(data)); opts.CLIFile == "" {
			return fmt.Errorf("%s has no startup-config or exec; give -cli-file", opts.StartConf)
		}
	}
	if opts.VPPUnit != "" && *unitDir != "" {
		opts.UnitFile = filepath.Join(*unitDir, opts.VPPUnit)
	}
	if opts.Confirm < 10*time.Second {
		return errors.New("-confirm must be at least 10s")
	}
	service, err := NewService(opts, func() (vppAPI, error) { return dialVPP(opts.APISocket) })
	if err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return err
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
	maint := NewMaint(service, *unitDir, splitList(*units), splitList(*backup))
	go service.watch()
	log.Printf("listening on %s, editing %s and %s", *socket, opts.StartConf, opts.CLIFile)
	return (&http.Server{
		Handler: service.Handler(maint), ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if unix, ok := c.(*net.UnixConn); ok {
				return context.WithValue(ctx, connKey{}, unix)
			}
			return ctx
		},
	}).Serve(listener)
}
