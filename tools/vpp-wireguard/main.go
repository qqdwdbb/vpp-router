package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/binapi/vlib"
)

// vpp-wireguard owns the WireGuard tunnels of a VPP router: what they are, whether they run,
// and putting them back after VPP restarts. VPP's own startup knows nothing about them.
func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "import" {
		err = runImport(os.Args[2:])
	} else {
		err = run(os.Args[1:])
	}
	if err != nil {
		log.Fatal(err)
	}
}

const defaultConfigDir = "/etc/vpp/wireguard"

const maxBody = 4 << 20

// system is what a change does to the machine.
type system interface {
	vppCLI(string) (string, error) // run one VPP CLI command
	unitActive(string) bool        // whether a systemd unit has finished starting
	nft(string) error              // apply an atomic nftables batch
	ip(...string) error            // run one iproute2 command on the host
}

func (s *realSystem) ip(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *realSystem) nft(batch string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

type realSystem struct{ apiSocket string }

// vppCLI runs one command over the API socket on a connection of its own, as changes are rare.
func (s *realSystem) vppCLI(command string) (string, error) {
	conn, err := govpp.Connect(s.apiSocket)
	if err != nil {
		return "", err
	}
	defer conn.Disconnect()
	channel, err := conn.NewAPIChannel()
	if err != nil {
		return "", err
	}
	defer channel.Close()
	channel.SetReplyTimeout(5 * time.Second)
	reply := &vlib.CliInbandReply{}
	if err := channel.SendRequest(&vlib.CliInband{Cmd: command}).ReceiveReply(reply); err != nil {
		return "", err
	}
	if reply.Retval != 0 {
		return "", fmt.Errorf("VPP CLI rejected command (code %d)", reply.Retval)
	}
	return reply.Reply, nil
}

func (s *realSystem) unitActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".vpp-wireguard-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
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
func (a *Service) Handler() http.Handler {
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wireguard", func(w http.ResponseWriter, r *http.Request) {
		state, err := a.WireGuard()
		reply(w, state, err)
	})
	mux.HandleFunc("POST /wireguard/config", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Name       string `json:"name"`
			Source     string `json:"source"`
			Text       string `json:"text"`
			AfterUp    string `json:"after_up"`
			BeforeDown string `json:"before_down"`
			ExitVia    string `json:"exit_via"`
			// DNS, any object, enables DNS forwarding; its fields are ignored.
			DNS *WireGuardDNS `json:"dns"`
		}
		if decode(w, r, &request) {
			state, err := a.AddWireGuardConfig(request.Name, request.Source, request.Text, request.AfterUp, request.BeforeDown, request.ExitVia, request.DNS != nil, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /wireguard/config/source", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Interface string `json:"interface"`
			Source    string `json:"source"`
		}
		if decode(w, r, &request) {
			state, err := a.UpdateWireGuardSource(request.Interface, request.Source, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /wireguard/config/edit", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Interface string        `json:"interface"`
			Source    string        `json:"source"`
			DNS       *WireGuardDNS `json:"dns"`
		}
		if decode(w, r, &request) {
			state, err := a.UpdateWireGuardSettings(request.Interface, request.Source, request.DNS, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /wireguard/config/dns", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Interface string        `json:"interface"`
			DNS       *WireGuardDNS `json:"dns"`
		}
		if decode(w, r, &request) {
			state, err := a.UpdateWireGuardDNS(request.Interface, request.DNS, user(r))
			reply(w, state, err)
		}
	})
	for path, action := range map[string]func(string, string) (*WireGuardState, error){
		"start": a.StartWireGuardConfig, "stop": a.StopWireGuardConfig, "delete": a.DeleteWireGuardConfig,
	} {
		mux.HandleFunc("POST /wireguard/config/"+path, func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				Interface string `json:"interface"`
			}
			if decode(w, r, &request) {
				state, err := action(request.Interface, user(r))
				reply(w, state, err)
			}
		})
	}
	mux.HandleFunc("POST /wireguard/peer", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Interface  string   `json:"interface"`
			PublicKey  string   `json:"public_key"`
			Name       string   `json:"name"`
			AllowedIPs []string `json:"allowed_ips"`
		}
		if decode(w, r, &request) {
			state, err := a.AddWireGuardPeer(request.Interface, request.PublicKey, request.Name, request.AllowedIPs, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /wireguard/peer/delete", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Interface string `json:"interface"`
			PublicKey string `json:"public_key"`
		}
		if decode(w, r, &request) {
			state, err := a.DeleteWireGuardPeer(request.Interface, request.PublicKey, user(r))
			reply(w, state, err)
		}
	})
	return mux
}

func run(args []string) error {
	fs := flag.NewFlagSet("vpp-wireguard", flag.ContinueOnError)
	opts := Options{}
	socket := fs.String("socket", "/run/vpp-wireguard/wireguard.sock", "socket for the management panel")
	fs.StringVar(&opts.ConfigDir, "config-dir", defaultConfigDir, "WireGuard configurations and peer names")
	fs.StringVar(&opts.Names, "names", "", "JSON file naming peers, the panel's --vpn-names; defaults to names.json in -config-dir")
	fs.StringVar(&opts.APISocket, "api-socket", "/run/vpp/api.sock", "VPP API socket")
	fs.StringVar(&opts.NATInterface, "nat-interface", "", "NAT44 outside interface on which listening ports of new configurations are opened")
	fs.StringVar(&opts.ExitsFile, "exits-file", "/run/vpp-wireguard/exits.json", "where started configurations usable as exits are published, for gate-admin")
	fs.StringVar(&opts.VPPUnit, "vpp-unit", "", "systemd unit that configures VPP; configurations are restored once it is active. Without it, 30 seconds after VPP's socket appears")
	fs.StringVar(&opts.GateConfig, "gate-config", "/etc/vpp/egress-gate.json", "DNS Gate entry configuration used by WireGuard DNS forwarding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	if opts.Names == "" {
		opts.Names = filepath.Join(opts.ConfigDir, "names.json")
	}
	service, err := NewService(opts, &realSystem{apiSocket: opts.APISocket})
	if err != nil {
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
	go service.watchVPP()
	log.Printf("listening on %s, configuration in %s", *socket, opts.ConfigDir)
	return (&http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}

func runImport(args []string) error {
	fs := flag.NewFlagSet("vpp-wireguard import", flag.ContinueOnError)
	configDir := fs.String("config-dir", defaultConfigDir, "WireGuard configurations and peer names")
	name := fs.String("name", "", "name for the configuration")
	file := fs.String("file", "", "VPP CLI file that creates the interface")
	afterUp := fs.String("after-up", "", "file of VPP commands to run after the interface is up")
	beforeDown := fs.String("before-down", "", "file of VPP commands undoing them, run before it goes")
	started := fs.Bool("started", false, "the interface exists now, and should be restored after VPP restarts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *file == "" {
		return fmt.Errorf("-name and -file are required")
	}
	stored, err := importConfig(*configDir, *name, *file, *afterUp, *beforeDown, *started)
	if err != nil {
		return err
	}
	fmt.Printf("imported %s as %q: %d peers, %d after-up and %d before-down commands, started=%v\n",
		stored.iface(), stored.Name, len(stored.Peers), len(stored.AfterUp), len(stored.BeforeDown), stored.Enabled)
	return nil
}
