package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
)

//go:embed web
var webFiles embed.FS

const (
	maxQueryKeys  = 64
	maxQueryRange = 7 * 24 * 3600
)

func serveVPN(vpn *VPNService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(vpn.Report())
	})
}

// NewHandler serves the dashboard and its read-only JSON endpoints.
func NewHandler(collector *Collector, store *Store, nat *NATService, vpn *VPNService) http.Handler {
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	// The pages are one document that shows the part its path names.
	for _, page := range []string{"GET /routes", "GET /vpn", "GET /interfaces", "GET /proxy", "GET /firewall", "GET /system", "GET /lan"} {
		mux.HandleFunc(page, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, static, "index.html")
		})
	}
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(collector.Status())
	})
	mux.HandleFunc("GET /api/nat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(nat.Report())
	})
	mux.Handle("GET /api/vpn", serveVPN(vpn))
	mux.HandleFunc("GET /api/lan/traffic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		traffic := &LANTraffic{Rates: []LANRate{}}
		if collector.meter != nil {
			traffic = collector.meter.Traffic()
		}
		json.NewEncoder(w).Encode(traffic)
	})
	mux.HandleFunc("GET /api/series", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		seconds, err := strconv.ParseInt(query.Get("range"), 10, 64)
		if err != nil || seconds <= 0 || seconds > maxQueryRange {
			http.Error(w, "range must be seconds, up to 7 days", http.StatusBadRequest)
			return
		}
		keys := query["key"]
		if len(keys) == 0 || len(keys) > maxQueryKeys {
			http.Error(w, "between 1 and 64 key parameters are required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(store.Query(keys, seconds).AppendJSON(nil))
	})
	return mux
}
