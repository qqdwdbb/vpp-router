package gate

import (
	"errors"
	"fmt"
	"log"
	"time"
)

var (
	// errVPPInterfaceMissing means a route needs an interface VPP does not have yet: its
	// startup CLI may still be running, or a tunnel may not be up yet.
	errVPPInterfaceMissing = errors.New("VPP route interface does not exist")

	vppWaitInterval = time.Second
	failureLogEvery = time.Minute
)

// probeVPP answers whether VPP can be used now, and which VPP instance answered.
// It uses both of Gate's ways in, as the sockets do not appear at the same time.
func probeVPP(backend Backend) (string, error) {
	generation, err := backend.Generation()
	if err != nil {
		return "", err
	}
	if err := backend.Apply(nil); err != nil {
		return "", err
	}
	if _, err := backend.CLI("show version"); err != nil {
		return "", err
	}
	return generation, nil
}

// startWithVPP runs start once VPP can take it, and returns false if stop came first.
// Failures caused by VPP are waited out. Any other failure of start is returned, and
// telling them apart relies on asking VPP again rather than on the wording of an error.
func startWithVPP(stop <-chan struct{}, probe func() (string, error), start func() error) (bool, error) {
	waiting := failureLog{what: "waiting for VPP"}
	for {
		generation, err := probe()
		if err == nil {
			err = start()
			if err == nil {
				waiting.recovered("VPP is ready")
				return true, nil
			}
			if !errors.Is(err, errVPPInterfaceMissing) {
				if current, probeErr := probe(); probeErr == nil && current == generation {
					return false, err
				}
			}
		}
		waiting.failed(err)
		select {
		case <-stop:
			return false, nil
		case <-time.After(vppWaitInterval):
		}
	}
}

// failureLog keeps a failure that repeats every few seconds from filling the journal.
// It logs a new failure at once, the same one only now and then, and the end of it.
type failureLog struct {
	what     string
	message  string
	since    time.Time
	reported time.Time
	repeats  int
	failures int
}

func (l *failureLog) failed(err error) {
	now := time.Now()
	if l.failures == 0 {
		l.since = now
	}
	l.failures++
	if message := err.Error(); message != l.message {
		l.message, l.reported, l.repeats = message, now, 0
		log.Printf("%s: %s", l.what, message)
		return
	}
	l.repeats++
	if now.Sub(l.reported) >= failureLogEvery {
		log.Printf("%s: %s (%d more times in %s)", l.what, l.message, l.repeats, now.Sub(l.reported).Round(time.Second))
		l.reported, l.repeats = now, 0
	}
}

// recovered logs what stopped the failures, and logs nothing if there were none.
func (l *failureLog) recovered(what string) {
	if l.failures == 0 {
		return
	}
	log.Printf("%s after %s (%s)", what, time.Since(l.since).Round(time.Second), failureCount(l.failures))
	*l = failureLog{what: l.what}
}

func failureCount(n int) string {
	if n == 1 {
		return "1 failure"
	}
	return fmt.Sprintf("%d failures", n)
}
