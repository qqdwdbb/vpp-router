package gate

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunCmdTimesOut(t *testing.T) {
	old := commandTimeout
	commandTimeout = 50 * time.Millisecond
	defer func() { commandTimeout = old }()
	start := time.Now()
	_, err := runCmd("sleep", "10")
	if err == nil {
		t.Fatal("expected timeout")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func TestProcessStatHandlesSpacesAndRejectsZombies(t *testing.T) {
	text := "123 (vpp worker name) S " + strings.Repeat("0 ", 18) + "987 0"
	start, err := parseProcessStat(text)
	if err != nil || start != "987" {
		t.Fatalf("start %q err %v", start, err)
	}
	if _, err := parseProcessStat(strings.Replace(text, ") S ", ") Z ", 1)); err == nil {
		t.Fatal("zombie accepted")
	}
}

func TestGenerationIdentityUsesSocketCtime(t *testing.T) {
	path := t.TempDir() + "/cli.sock"
	if err := os.WriteFile(path, []byte("sock"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := stampOf(path)
	if err != nil {
		t.Fatal(err)
	}
	identity := [3]any{"vpp", st.Ino, st.Ctime}
	if identity[1] == uint64(0) && identity[2] == int64(0) {
		t.Fatal("socket identity missing inode/ctime")
	}
	if identity[2] != st.Ctime {
		t.Fatal("generation identity did not use ctime")
	}
}
