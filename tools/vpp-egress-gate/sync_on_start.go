package gate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
)

// systemIsBooting reads systemctl's answer, which is on stdout whatever its exit status.
func systemIsBooting(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	state := strings.TrimSpace(string(out))
	return state == "initializing" || state == "starting"
}

// SyncOnStart is the --sync-on-start mode, which runs before Gate on every start so that a
// restart is all a changed configuration needs. Its unit ignores a failure: Gate then
// starts from the last successful sync, as a typing error should not cost DNS.
//
// A boot does not sync. It comes up from the last sync whatever state the JSON is in, and
// VPP may be running its startup CLI, which creates the same devices a sync would add.
func SyncOnStart(configPath string) error {
	if systemIsBooting(context.Background()) {
		log.Printf("devices: the system is booting, so Gate starts from the last sync; restart it to apply %s", configPath)
		return nil
	}
	if _, err := os.Stat(configPath); errors.Is(err, fs.ErrNotExist) {
		log.Printf("devices: %s does not exist, so Gate starts from the last sync", configPath)
		return nil
	}
	syncIgnoresListProblems = true
	defer func() { syncIgnoresListProblems = false }()
	if err := SyncDevices(configPath, false); err != nil {
		return fmt.Errorf("%s is not applied, and Gate starts from the last successful sync: %w", configPath, err)
	}
	return nil
}
