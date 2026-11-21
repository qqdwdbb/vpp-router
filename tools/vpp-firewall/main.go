// vpp-firewall controls what a VPP router lets in from its WAN: IPv4 port forwards and ports
// open to VPP itself (NAT44-EI static and identity mappings), ping, and a stateful IPv6 inbound
// firewall (acl plugin). VPP keeps none of it across a restart, so this puts it back.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const maxBody = 1 << 16

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /firewall", func(w http.ResponseWriter, r *http.Request) {
		reply(w, s.State(), nil)
	})
	mux.HandleFunc("POST /firewall/forward", func(w http.ResponseWriter, r *http.Request) {
		var f Forward
		if decode(w, r, &f) {
			state, err := s.AddForward(f, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /firewall/port", func(w http.ResponseWriter, r *http.Request) {
		var p Port
		if decode(w, r, &p) {
			state, err := s.AddPort(p, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /firewall/ipv6/rule", func(w http.ResponseWriter, r *http.Request) {
		var rule IPv6Rule
		if decode(w, r, &rule) {
			state, err := s.AddIPv6Rule(rule, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /firewall/delete", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID int `json:"id"`
		}
		if decode(w, r, &request) {
			state, err := s.Delete(request.ID, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /firewall/ping", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Allow bool `json:"allow"`
		}
		if decode(w, r, &request) {
			state, err := s.SetPing(request.Allow, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /firewall/ipv6", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Enable bool `json:"enable"`
		}
		if decode(w, r, &request) {
			state, err := s.SetIPv6Firewall(request.Enable, user(r))
			reply(w, state, err)
		}
	})
	return mux
}

func run(args []string) error {
	fs := flag.NewFlagSet("vpp-firewall", flag.ContinueOnError)
	opts := Options{}
	socket := fs.String("socket", "/run/vpp-firewall/firewall.sock", "socket for the management panel")
	fs.StringVar(&opts.ConfigFile, "config", "/etc/vpp/firewall.json", "the firewall's rules")
	fs.StringVar(&opts.APISocket, "api-socket", "/run/vpp/api.sock", "VPP API socket")
	fs.StringVar(&opts.VPPUnit, "vpp-unit", "", "systemd unit that configures VPP; rules are applied once it is active. Without it, 30 seconds after VPP's socket appears")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	service, err := NewService(opts, func() (vppAPI, error) { return dialVPP(opts.APISocket) })
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
	go service.watch()
	log.Printf("listening on %s, rules in %s", *socket, opts.ConfigFile)
	return (&http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
