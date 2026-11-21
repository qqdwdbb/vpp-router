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

// vpp-proxy manages the upstream of the sing-box proxy entry for the management panel: a
// wizard's profile turned into upstream.json, nodes read from sing-box configurations, share
// links and subscriptions, tests through a throwaway sing-box, and starting and stopping it.
func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

const maxBody = 4 << 20

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".vpp-proxy-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
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
		Profile *Profile `json:"profile"`
		URL     string   `json:"url"`
		Kind    string   `json:"kind"`
		Text    string   `json:"text"`
		Index   int      `json:"index"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy", func(w http.ResponseWriter, r *http.Request) { reply(w, s.State(), nil) })
	mux.HandleFunc("GET /proxy/exits", func(w http.ResponseWriter, r *http.Request) { reply(w, s.Exits(), nil) })
	post := func(path string, handle func(request, string) (any, error)) {
		mux.HandleFunc("POST /proxy/"+path, func(w http.ResponseWriter, r *http.Request) {
			var q request
			if decode(w, r, &q) {
				value, err := handle(q, user(r))
				reply(w, value, err)
			}
		})
	}
	post("apply", func(q request, u string) (any, error) {
		if q.Profile == nil {
			return nil, errEmptyProfile
		}
		return s.Apply(*q.Profile, u)
	})
	post("clear", func(_ request, u string) (any, error) { return s.Clear(u) })
	post("test", func(q request, _ string) (any, error) { return s.Test(q.Profile, q.URL) })
	post("parse", func(q request, _ string) (any, error) {
		nodes, err := s.Parse(q.Kind, q.Text)
		return map[string]any{"nodes": nodes}, err
	})
	post("subscription", func(q request, _ string) (any, error) { return s.Subscribe(q.URL) })
	post("subscription/update", func(_ request, u string) (any, error) { return s.UpdateSubscription(u) })
	post("subscription/use", func(q request, u string) (any, error) { return s.UseSubscriptionNode(q.Index, u) })
	post("subscription/delete", func(_ request, u string) (any, error) { return s.DeleteSubscription(u) })
	post("subscription/test", func(q request, _ string) (any, error) { return s.TestSubscriptionNode(q.Index, q.URL) })
	for _, action := range []string{"start", "stop", "restart"} {
		post(action, func(_ request, u string) (any, error) { return s.Unit(action, u) })
	}
	return mux
}

type plainError string

func (e plainError) Error() string { return string(e) }

const errEmptyProfile = plainError("没有上游配置")

func run(args []string) error {
	fs := flag.NewFlagSet("vpp-proxy", flag.ContinueOnError)
	opts := Options{}
	socket := fs.String("socket", "/run/vpp-proxy/proxy.sock", "socket for the management panel")
	fs.StringVar(&opts.SingBoxDir, "sing-box-dir", "/etc/vpp/sing-box", "sing-box's configuration: entry.json and upstream.json")
	fs.StringVar(&opts.ConfigDir, "config-dir", "/etc/vpp/proxy", "the wizard's profile")
	fs.StringVar(&opts.StateDir, "state-dir", "/var/lib/vpp-proxy", "the subscription and test files")
	fs.StringVar(&opts.Unit, "unit", "vpp-router-sing-box.service", "the systemd unit running sing-box")
	fs.StringVar(&opts.Binary, "binary", "/usr/local/bin/sing-box", "sing-box")
	fs.StringVar(&opts.TestURL, "test-url", "https://www.gstatic.com/generate_204", "what a test requests through the upstream")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	service, err := NewService(opts, &realSystem{opts: opts})
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
	log.Printf("listening on %s, for %s", *socket, opts.SingBoxDir)
	return (&http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
