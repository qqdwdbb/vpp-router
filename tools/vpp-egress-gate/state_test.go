package gate

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDeferredStateExitReportsFlushError(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocked, "state.json")
	store := NewDeferredState([]string{path})
	store.Enter()
	store.Write(path, map[string]any{"version": 1})
	if err := store.Exit(); err == nil {
		t.Fatal("Exit ignored Flush error")
	}
}

func TestSharedLockCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interface.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if release, err := sharedLockFilesContext(ctx, []string{path}); err == nil {
		release()
		t.Fatal("exclusive lock should block until cancellation")
	}
}

func TestPrefixLockCancellation(t *testing.T) {
	p := NewPrefixLocks()
	key := RouteKey{0, "198.51.100.77/32"}
	release := p.Hold([]RouteKey{key})
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if unlock, err := p.HoldContext(ctx, []RouteKey{key}); err == nil {
		unlock()
		t.Fatal("held prefix should block until cancellation")
	}
}

func TestDeferredStateExitFlushes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := NewDeferredState([]string{path})
	store.Enter()
	store.Write(path, map[string]any{"version": 1, "generation": "abc"})
	if err := store.Exit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
