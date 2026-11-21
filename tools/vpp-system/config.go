package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config is what this program puts back after VPP starts, and the governors it sets at boot.
// The thread layout and NAT settings are in VPP's own files instead.
type Config struct {
	// RxModes is the receive mode of every queue of an interface, by interface name.
	RxModes map[string]string `json:"rx_modes,omitempty"`
	// RxPlacement is the thread polling a queue, by interface name and queue: 0 is the main
	// thread, n is worker n-1.
	RxPlacement map[string]map[uint32]uint32 `json:"rx_placement,omitempty"`
	// Governors is the cpufreq governor by policy, such as "policy4": "ondemand".
	Governors map[string]string `json:"governors,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) clone() *Config {
	data, _ := json.Marshal(c)
	out := &Config{}
	json.Unmarshal(data, out)
	return out
}

func (c *Config) save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".vpp-system-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// fileMode keeps an existing file's permissions.
func fileMode(path string) os.FileMode {
	if info, err := os.Stat(path); err == nil {
		return info.Mode().Perm()
	}
	return 0o644
}
