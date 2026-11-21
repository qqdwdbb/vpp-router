package gate

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"
)

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Run is the vpp-egress-gate CLI entry point.
// exitCheckTicks is how often, in two-second ticks, exits are checked when none is missing.
const exitCheckTicks = 5

func Run(args []string) (err error) {
	fs := flag.NewFlagSet("vpp-egress-gate", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/vpp/egress-gate.json", "gate configuration JSON")
	syncDevices := fs.Bool("sync-devices", false, "create the TUN and TAP devices the configuration asks for, then exit")
	syncOnStart := fs.Bool("sync-on-start", false, "what the service runs before Gate: --sync-devices, except during a boot")
	flush := fs.Bool("flush", false, "remove the routes and rules Gate put in place, with its route ledger and leases, then exit")
	dryRun := fs.Bool("dry-run", false, "with --sync-devices or --flush, print the plan without changing anything")
	setupLinks := fs.Bool("setup-links", false, "restore the Linux side of the devices from the last sync, then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetFlags(0)
	log.SetPrefix("")
	hostSettingsFile = filepath.Join(deviceStateDir, "host-settings.json")
	if *setupLinks {
		if *syncDevices || *flush || *dryRun {
			return fmt.Errorf("--setup-links takes no other mode")
		}
		return SetupLinks()
	}
	if *syncOnStart {
		if *syncDevices || *flush || *dryRun {
			return fmt.Errorf("--sync-on-start takes no other mode")
		}
		return SyncOnStart(*configPath)
	}
	if *flush {
		if *syncDevices {
			return fmt.Errorf("--flush takes no other mode")
		}
		return Flush(*configPath, *dryRun)
	}
	if *syncDevices {
		return SyncDevices(*configPath, *dryRun)
	}
	if *dryRun {
		return fmt.Errorf("--dry-run requires --sync-devices or --flush")
	}
	warnUnknownFields(*configPath)
	g, err := LoadGateFile(*configPath)
	if err != nil {
		return err
	}
	routePath := g.RouteConfig
	if routePath == "" {
		routePath = *configPath
	}
	domainPath := g.DomainRoutesFile
	if domainPath == "" && g.HasRoutes {
		domainPath = *configPath
	}
	routeCfg, err := LoadConfig(routePath)
	if err != nil {
		return err
	}
	store := NewDeferredState([]string{routeCfg.StateFile, g.LeaseFile})
	store.Enter()
	defer func() {
		if flushErr := store.Exit(); flushErr != nil {
			if err == nil {
				err = flushErr
			} else {
				log.Printf("state flush failed: %s", flushErr)
			}
		}
	}()

	// Configuration is loaded once, at startup.
	controller, err := NewController(routePath, g.LeaseFile, NewVPPBackend, domainPath)
	if err != nil {
		return err
	}
	gate := NewGate(controller, g.Upstream)
	stop := make(chan struct{})
	waitSignals(stop)

	lock, err := exclusiveLock(gateLockPath)
	if err != nil {
		return err
	}
	defer lock.Close()

	// A Gate that was killed left its redirect, which sends queries to a port nobody is on,
	// and VPP may keep this one from listening for a long time.
	if clearErr := clearDNSHijack(); clearErr != nil {
		log.Printf("DNS hijack left by an earlier run not removed: %s", clearErr)
	}
	controller.refreshLinuxUnderlay(context.Background())
	cfg, _ := controller.loaded()
	backend := NewVPPBackend(cfg)
	defaults := newDefaultRouteKeeper(func() *Config { cfg, _ := controller.loaded(); return cfg }, vppDefaultRouteAPI{cfg: cfg, backend: backend})
	if err = StartStateServer(cfg, stop, defaults.Status); err != nil {
		return err
	}
	// Subscribe before the first reconciliation so that no link change falls between them.
	var linkEvents chan struct{}
	if hasLinuxExits(cfg) {
		if source, watchErr := openLinkEvents(); watchErr != nil {
			log.Printf("Linux exit link watcher unavailable, relying on periodic checks: %s", watchErr)
		} else {
			defer source.Close()
			linkEvents = make(chan struct{}, 1)
			go watchLinkEvents(source, linuxExitInterfaces(cfg), interfaceNameByIndex, linkEventDelay, linkEvents)
		}
	}
	started, err := startWithVPP(stop, func() (string, error) { return probeVPP(backend) }, func() error {
		controller.refreshLinuxUnderlay(context.Background())
		if err := controller.Reconcile(context.Background(), nil, nil, false); err != nil {
			return err
		}
		if len(cfg.FakeIPPools) > 0 {
			if err := store.Flush(); err != nil {
				return err
			}
		}
		generation, err := backend.Generation()
		if err != nil {
			return err
		}
		store.lock.Lock()
		defer store.lock.Unlock()
		_, _, _, err = store.Ledger(cfg.StateFile, generation)
		return err
	})
	if err != nil || !started {
		return err
	}

	var servers []func()
	var serveWG sync.WaitGroup
	for _, listen := range g.Listen {
		udp, listenErr := listenPacket(listen.Host, listen.Port)
		if listenErr != nil {
			return listenErr
		}
		tcp, listenErr := listenStream(listen.Host, listen.Port)
		if listenErr != nil {
			udp.Close()
			return listenErr
		}
		serveWG.Add(2)
		go func() { defer serveWG.Done(); ServeUDP(udp, gate, stop) }()
		go func() { defer serveWG.Done(); ServeTCP(tcp, gate, stop) }()
		servers = append(servers, func() { udp.Close(); tcp.Close() })
	}
	if hijackErr := syncDNSHijack(g); hijackErr != nil {
		for _, closeFn := range servers {
			closeFn()
		}
		gate.Shutdown()
		serveWG.Wait()
		return hijackErr
	}
	if g.HijackDNS {
		defer func() { _ = clearDNSHijack() }()
	}
	// Linux redirects first: VPP sends queries to Linux only once it can answer them.
	hijackVPP := newVPPHijackKeeper(cfg, g, backend)
	hijackVPP.ensure()
	if len(g.HijackVPP) > 0 {
		defer clearVPPHijack(cfg)
	}
	log.Printf("DNS barrier listening on %v; backend %s:%d", g.Listen, g.Upstream.Host, g.Upstream.Port)
	defaults.ensure()
	lanPrefixes := newLANPrefixKeeper(g.LANInterfaces, vppDefaultRouteAPI{cfg: cfg, backend: backend}.session)
	lanPrefixes.tick()

	fullSync := false
	nextResync := time.Now().Add(time.Duration(cfg.MonitorResyncSeconds * float64(time.Second)))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	linkChanged := false
	background := failureLog{what: "background reconciliation failed"}
	// Exits come and go with the services that own them. While one is missing it is looked for on every tick,
	// so that its rules return quickly; otherwise a slower check finds one that went away.
	exitWait, anyMissing := 0, true
	checkExits := func() {
		if exitWait++; !anyMissing && exitWait < exitCheckTicks {
			return
		}
		exitWait = 0
		changed, missing, err := controller.exitsChanged(context.Background())
		if err != nil {
			return
		}
		anyMissing = missing
		fullSync = fullSync || changed
	}
	tick := func() {
		if fullSync || linkChanged || time.Now().After(nextResync) {
			controller.refreshLinuxUnderlay(context.Background())
			cfg, _ := controller.loaded()
			if recErr := controller.Reconcile(context.Background(), nil, nil, fullSync); recErr != nil {
				background.failed(recErr)
				return
			}
			background.recovered("background reconciliation recovered")
			fullSync = false
			linkChanged = false
			nextResync = time.Now().Add(time.Duration(cfg.MonitorResyncSeconds * float64(time.Second)))
		}
	}
	for {
		select {
		case <-stop:
			for _, closeFn := range servers {
				closeFn()
			}
			serveWG.Wait()
			return nil
		case <-ticker.C:
			checkExits()
			exitsMoved := fullSync
			tick()
			hijackVPP.ensure()
			defaults.tick(exitsMoved)
			lanPrefixes.tick()
		case <-linkEvents:
			linkChanged = true
			tick()
			defaults.tick(true)
		}
	}
}
