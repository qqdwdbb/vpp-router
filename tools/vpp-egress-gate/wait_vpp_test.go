package gate

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

// captureWaitLog also drops the timestamps, so that a test can compare whole lines.
func captureWaitLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	flags := log.Flags()
	log.SetFlags(0)
	t.Cleanup(func() { log.SetFlags(flags) })
	return captureLog(t)
}

func fastVPPWait(t *testing.T) {
	t.Helper()
	old := vppWaitInterval
	vppWaitInterval = time.Millisecond
	t.Cleanup(func() { vppWaitInterval = old })
}

// script answers each call with the next entry, and repeats the last one.
func script[T any](answers ...T) func() T {
	i := 0
	return func() T {
		answer := answers[i]
		if i < len(answers)-1 {
			i++
		}
		return answer
	}
}

type probeAnswer struct {
	generation string
	err        error
}

func probeOf(answers ...probeAnswer) func() (string, error) {
	next := script(answers...)
	return func() (string, error) {
		answer := next()
		return answer.generation, answer.err
	}
}

func TestStartWithVPPWaitsUntilVPPAnswers(t *testing.T) {
	fastVPPWait(t)
	out := captureWaitLog(t)
	gone := errors.New("stat /run/vpp/cli.sock: no such file or directory")
	starts := 0
	started, err := startWithVPP(make(chan struct{}),
		probeOf(probeAnswer{err: gone}, probeAnswer{err: gone}, probeAnswer{generation: "a"}),
		func() error { starts++; return nil })
	if err != nil || !started {
		t.Fatalf("started=%v err=%v", started, err)
	}
	if starts != 1 {
		t.Fatalf("started %d times while VPP was away", starts)
	}
	text := out.String()
	if strings.Count(text, "waiting for VPP: "+gone.Error()) != 1 {
		t.Fatalf("the same failure was not merged:\n%s", text)
	}
	if !strings.Contains(text, "VPP is ready after") || !strings.Contains(text, "2 failures") {
		t.Fatalf("the end of the wait is not logged:\n%s", text)
	}
}

func TestStartWithVPPIsSilentWhenVPPIsAlreadyThere(t *testing.T) {
	out := captureWaitLog(t)
	started, err := startWithVPP(make(chan struct{}), probeOf(probeAnswer{generation: "a"}), func() error { return nil })
	if err != nil || !started {
		t.Fatalf("started=%v err=%v", started, err)
	}
	if out.Len() != 0 {
		t.Fatalf("logged without waiting:\n%s", out)
	}
}

// The startup CLI has not created the interface yet, while VPP itself answers.
func TestStartWithVPPWaitsForAnInterface(t *testing.T) {
	fastVPPWait(t)
	captureWaitLog(t)
	missing := fmt.Errorf("VPP Binary API request failed: %w: tap-wg1", errVPPInterfaceMissing)
	starts := script[error](missing, missing, nil)
	started, err := startWithVPP(make(chan struct{}), probeOf(probeAnswer{generation: "a"}), starts)
	if err != nil || !started {
		t.Fatalf("started=%v err=%v", started, err)
	}
}

func TestStartWithVPPWaitsWhenVPPLeavesDuringTheStart(t *testing.T) {
	cases := map[string]probeAnswer{
		"it_is_gone":      {err: errors.New("VPP has no active invocation")},
		"it_is_restarted": {generation: "b"},
	}
	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			fastVPPWait(t)
			captureWaitLog(t)
			starts := script[error](errors.New("any wording at all"), nil)
			started, err := startWithVPP(make(chan struct{}),
				probeOf(probeAnswer{generation: "a"}, after, probeAnswer{generation: "b"}), starts)
			if err != nil || !started {
				t.Fatalf("started=%v err=%v", started, err)
			}
		})
	}
}

// Waiting would hide a fault VPP has no part in, such as a table that is taken.
func TestStartWithVPPReturnsAFailureThatIsNotVPP(t *testing.T) {
	fastVPPWait(t)
	captureWaitLog(t)
	fault := errors.New("table 100 is in use")
	started, err := startWithVPP(make(chan struct{}), probeOf(probeAnswer{generation: "a"}), func() error { return fault })
	if !errors.Is(err, fault) || started {
		t.Fatalf("started=%v err=%v", started, err)
	}
}

func TestStartWithVPPStopsWhileWaiting(t *testing.T) {
	captureWaitLog(t)
	stop := make(chan struct{})
	close(stop)
	started, err := startWithVPP(stop, probeOf(probeAnswer{err: errors.New("not yet")}), func() error {
		t.Fatal("started without VPP")
		return nil
	})
	if err != nil || started {
		t.Fatalf("started=%v err=%v", started, err)
	}
}

func TestFailureLogMergesRepeats(t *testing.T) {
	out := captureWaitLog(t)
	l := failureLog{what: "reconciliation failed"}
	l.recovered("reconciliation recovered")
	if out.Len() != 0 {
		t.Fatalf("recovered from nothing:\n%s", out)
	}
	for i := 0; i < 5; i++ {
		l.failed(errors.New("A"))
	}
	l.failed(errors.New("B"))
	l.failed(errors.New("B"))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if want := []string{"reconciliation failed: A", "reconciliation failed: B"}; len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("got %q", lines)
	}

	// Long enough has passed: the same failure is reported again, with its count.
	out.Reset()
	l.reported = time.Now().Add(-2 * failureLogEvery)
	l.failed(errors.New("B"))
	if text := out.String(); !strings.Contains(text, "reconciliation failed: B (2 more times in 2m0s)") {
		t.Fatalf("got %q", text)
	}

	out.Reset()
	l.recovered("reconciliation recovered")
	if text := out.String(); !strings.Contains(text, "reconciliation recovered after") || !strings.Contains(text, "8 failures") {
		t.Fatalf("got %q", text)
	}

	// After a recovery the same failure is news again.
	out.Reset()
	l.failed(errors.New("A"))
	if text := out.String(); text != "reconciliation failed: A\n" {
		t.Fatalf("got %q", text)
	}
}
