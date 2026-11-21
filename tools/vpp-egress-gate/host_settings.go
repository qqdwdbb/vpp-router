package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
)

// hostSettingsFile records what a host setting was before this program changed it, so
// that uninstall.py can put it back. Only the program itself sets it, not its tests.
var (
	hostSettingsFile string
	hostSettingsMu   sync.Mutex
)

type hostSetting struct {
	Name string `json:"name"`
	Was  string `json:"was"`
	Set  string `json:"set"`
}

// recordHostSetting keeps the first value seen and the order of the changes. It runs
// before the change: a lost record would make the old value unrecoverable. Gate and a
// device sync can run together, so a file lock guards the update.
func recordHostSetting(name, was, set string) error {
	if hostSettingsFile == "" {
		return nil
	}
	hostSettingsMu.Lock()
	defer hostSettingsMu.Unlock()
	if err := os.MkdirAll(deviceStateDir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(hostSettingsFile+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	var record struct {
		Settings []hostSetting `json:"settings"`
	}
	data, err := os.ReadFile(hostSettingsFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("%s: %w", hostSettingsFile, err)
		}
	}
	for _, setting := range record.Settings {
		if setting.Name == name {
			return nil
		}
	}
	record.Settings = append(record.Settings, hostSetting{Name: name, Was: was, Set: set})
	return durableJSON(hostSettingsFile, map[string]any{"settings": record.Settings})
}
