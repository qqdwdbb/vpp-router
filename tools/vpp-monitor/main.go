// vpp-monitor reads VPP's stats segment with GoVPP and serves a dashboard from one binary.
// It is meant for small hosts: a read touches only shared memory, history stays in fixed
// rings in RAM, and the charts are drawn by the browser.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
)

// connectWait is how long GoVPP waits for a missing socket. It stays short because the
// collector retries, and a tick must not block.
const connectWait = 100 * time.Millisecond

func main() {
	socket := flag.String("socket", adapter.DefaultStatsSocket, "VPP stats socket")
	strokeBinary := flag.String("stroke", "/usr/lib/ipsec/stroke", "strongSwan's stroke client")
	ipsecSocket := flag.String("ipsec-socket", "", "charon's stroke socket when it is not the default, such as unix:///run/rk3588-strongswan/charon.ctl")
	vpnNames := flag.String("vpn-names", "", "JSON file mapping WireGuard public keys to client names")
	runsFile := flag.String("vpp-runs", "/var/lib/vpp-monitor/vpp-runs.json", "history of VPP's starts")
	gateSocket := flag.String("gate-admin-socket", "/run/gate-admin/admin.sock", "gate-admin's socket, used by the routes page")
	wireguardSocket := flag.String("wireguard-socket", "/run/vpp-wireguard/wireguard.sock", "vpp-wireguard's socket, used by the VPN page")
	interfacesSocket := flag.String("interfaces-socket", "/run/vpp-interfaces/interfaces.sock", "vpp-interfaces' socket, used by the interfaces page")
	lanMeterFile := flag.String("lan-meter", "/run/vpp-interfaces/meter.json", "the LAN meter's rules from vpp-interfaces, for per-device traffic; empty turns it off")
	proxySocket := flag.String("proxy-socket", "/run/vpp-proxy/proxy.sock", "vpp-proxy's socket, used by the proxy page")
	firewallSocket := flag.String("firewall-socket", "/run/vpp-firewall/firewall.sock", "vpp-firewall's socket, used by the firewall page")
	systemSocket := flag.String("system-socket", "/run/vpp-system/system.sock", "vpp-system's socket, used by the system page")
	apiSocket := flag.String("api-socket", "/run/vpp/api.sock", "VPP API socket, used only while connections are being viewed")
	listen := flag.String("listen", "127.0.0.1:9480", "address of the dashboard")
	fast := flag.Duration("interval", time.Second, "interface counter interval")
	slow := flag.Duration("slow-interval", 10*time.Second, "interval for the remaining counters; divides 60s and is a multiple of -interval")
	stale := flag.Duration("stale-after", 30*time.Second, "treat VPP as gone when /sys/heartbeat is unchanged this long; must exceed statseg update-interval")
	authFile := flag.String("auth-file", "/var/lib/vpp-monitor/auth.json", "administrator credentials")
	certFile := flag.String("tls-cert", "/var/lib/vpp-monitor/tls.crt", "TLS certificate, created self-signed if missing")
	keyFile := flag.String("tls-key", "/var/lib/vpp-monitor/tls.key", "TLS key, created with the certificate")
	setPassword := flag.Bool("set-password", false, "read a password from standard input, store it for -user and exit")
	user := flag.String("user", "admin", "administrator name for -set-password")
	flag.Parse()
	if *setPassword {
		if err := storePassword(*authFile, *user); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("password stored for %s in %s; restart the service to use it\n", *user, *authFile)
		return
	}
	if err := checkIntervals(*fast, *slow, *stale); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// Workers poll on their cores; one thread is enough here and limits what can disturb them.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
	// GoVPP logs every failed connection. The collector logs state changes instead.
	statsclient.Log.SetOutput(io.Discard)

	store := NewStore(tiersFor(int64(*fast/time.Second), int64(*slow/time.Second)))
	collector := NewCollector(Config{Fast: *fast, Slow: *slow, StaleAfter: *stale}, store, func() (adapter.StatsAPI, error) {
		client := statsclient.NewStatsClient(*socket, statsclient.SetSocketRetryTimeout(connectWait))
		if err := client.Connect(); err != nil {
			client.Disconnect()
			return nil, err
		}
		return &gaugeClient{StatsClient: client, socket: *socket}, nil
	})

	collector.runs = loadVPPRuns(*runsFile)
	if *lanMeterFile != "" {
		collector.meter = newLANMeter(*lanMeterFile)
	}
	labels := NewInterfaceLabels(func() (map[string]InterfaceInfo, error) { return readInterfaceLabels(*apiSocket) })
	collector.labels = labels
	nat := NewNATService(func() (natAPI, error) { return dialVPPNAT(*apiSocket, labels) })

	names, err := LoadVPNNames(*vpnNames)
	if err != nil {
		log.Fatal(err)
	}
	strongswanConf := ""
	if *ipsecSocket != "" {
		if strongswanConf, err = writeStrokeConfig(*ipsecSocket); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	vpn := NewVPNService(&systemVPN{apiSocket: *apiSocket, strokeBinary: *strokeBinary, strongswanConf: strongswanConf}, names)
	vpn.namesFile = *vpnNames

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	credentials, err := LoadCredentials(*authFile)
	if err != nil {
		log.Fatalf("cannot read the credentials (%v); create them with: vpp-monitor -set-password", err)
	}
	auth, err := NewAuth(credentials)
	if err != nil {
		log.Fatal(err)
	}
	if err := ensureCertificate(*certFile, *keyFile, *listen); err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	services := map[string]http.Handler{
		gateAPIPrefix:       NewAdminProxy(*gateSocket, credentials.User),
		wireGuardAPIPrefix:  RefreshVPNAfter(NewAdminProxy(*wireguardSocket, credentials.User), vpn),
		interfacesAPIPrefix: RefreshLabelsAfter(NewAdminProxy(*interfacesSocket, credentials.User), labels),
		proxyAPIPrefix:      NewAdminProxy(*proxySocket, credentials.User),
		firewallAPIPrefix:   NewAdminProxy(*firewallSocket, credentials.User),
		systemAPIPrefix:     NewAdminProxy(*systemSocket, credentials.User),
	}
	server := &http.Server{Handler: auth.Wrap(WithAdmin(NewHandler(collector, store, nat, vpn), services)), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	go func() {
		if err := server.ServeTLS(listener, *certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("dashboard on https://%s, reading %s", listener.Addr(), *socket)
	collector.Run(ctx)
}

func storePassword(path, user string) error {
	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return SetPassword(path, user, strings.TrimRight(line, "\r\n"))
}

func checkIntervals(fast, slow, stale time.Duration) error {
	if fast < time.Second || fast%time.Second != 0 || fast > time.Minute {
		return fmt.Errorf("-interval must be whole seconds, from 1s to 60s")
	}
	if slow%fast != 0 || (time.Minute)%slow != 0 {
		return fmt.Errorf("-slow-interval must be a multiple of -interval and divide 60s")
	}
	if stale <= slow {
		return fmt.Errorf("-stale-after must be longer than -slow-interval")
	}
	return nil
}
