package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

const (
	gateAPIPrefix       = "/api/gate"
	wireGuardAPIPrefix  = "/api/wireguard"
	interfacesAPIPrefix = "/api/interfaces"
	proxyAPIPrefix      = "/api/proxy"
	firewallAPIPrefix   = "/api/firewall"
	systemAPIPrefix     = "/api/system"
)

// NewAdminProxy forwards an API to the service on its local socket, so the
// panel's login is the only way in. The user name comes from here, never from the browser.
func NewAdminProxy(socket, user string) http.Handler {
	return &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = "gate-admin"
			request.Out.URL.Path = strings.TrimPrefix(request.In.URL.Path, "/api")
			request.Out.URL.RawPath = ""
			request.Out.Header.Set("X-Panel-User", user)
			request.Out.Header.Del("Cookie")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("gate admin: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "管理服务不可用"})
		},
	}
}

// RefreshVPNAfter makes the VPN page show a WireGuard change at once instead of a cached reading.
func RefreshVPNAfter(admin http.Handler, vpn *VPNService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin.ServeHTTP(w, r)
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, wireGuardAPIPrefix+"/") {
			vpn.Invalidate()
		}
	})
}

// RefreshLabelsAfter makes interface names follow an interface change, such as a new
// loopback address, at the next reading instead of minutes later.
func RefreshLabelsAfter(admin http.Handler, labels *InterfaceLabels) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin.ServeHTTP(w, r)
		if r.Method == http.MethodPost {
			labels.Forget()
		}
	})
}

// WithAdmin routes each service's API, by its prefix, to the service and everything else to next.
func WithAdmin(next http.Handler, services map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for prefix, service := range services {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				service.ServeHTTP(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
