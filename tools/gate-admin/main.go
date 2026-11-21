package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// gate-admin makes the management panel's changes to Gate: which exit a rule uses and what
// its lists hold. It is a process of its own because applying a change restarts Gate, and
// something has to outlive that restart to undo a change that fails.
func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("gate-admin", flag.ContinueOnError)
	opts := AdminOptions{}
	fs.StringVar(&opts.Config, "config", "/etc/vpp/egress-gate.json", "Gate's configuration: the one you edit, not the generated one")
	fs.StringVar(&opts.Unit, "unit", "vpp-egress-gate.service", "the systemd unit running Gate")
	fs.StringVar(&opts.Socket, "socket", "/run/gate-admin/admin.sock", "socket for the management panel")
	fs.StringVar(&opts.StateDir, "state-dir", "/var/lib/gate-admin", "backups of changes waiting for confirmation")
	fs.StringVar(&opts.ExitsFile, "exits-file", "/run/vpp-wireguard/exits.json,/run/vpp-interfaces/exits.json", "exits offered by the programs that own those interfaces, separated by commas")
	fs.StringVar(&opts.ListDir, "list-dir", defaultListDir, "where domain list files are created")
	fs.StringVar(&opts.CustomExits, "custom-exits", "/etc/vpp/gate-exits.json", "the exits set by hand in the panel: an interface and its next hops")
	fs.StringVar(&opts.ProxySocket, "proxy-socket", "/run/vpp-proxy/proxy.sock", "proxy service offering its configured TPROXY listeners")
	fs.DurationVar(&opts.Confirm, "confirm", time.Minute, "time to confirm a change before it is rolled back")
	gateBinary := fs.String("binary", "/usr/local/bin/vpp-egress-gate", "the Gate program that checks and syncs the configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	admin, err := NewAdmin(opts, &realAdminSystem{opts: opts, binary: *gateBinary})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.Socket), 0o700); err != nil {
		return err
	}
	os.Remove(opts.Socket)
	listener, err := net.Listen("unix", opts.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(opts.Socket, 0o600); err != nil {
		return err
	}
	log.Printf("admin service on %s, for %s", opts.Socket, opts.Config)
	return (&http.Server{Handler: admin.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
