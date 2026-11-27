package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const frequencySettle = 250 * time.Millisecond

// CPUFreq may queue the QoS/limits update before policy.min reflects the request.
// Other constraints may impose a higher effective minimum; that still meets a
// lower-bound guard. Read back with a bound, outside the packet path.
func waitFrequencyFloor(path string, khz int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		actual := readInt(path)
		if actual >= khz || !time.Now().Before(deadline) {
			return actual
		}
		time.Sleep(time.Millisecond)
	}
}

// Apply before VPP starts, and roll back partial application if any policy fails.
func applyFrequencyFloors(h host, floors map[string]frequencyFloor) error {
	var names []string
	for name := range floors {
		names = append(names, name)
	}
	slices.Sort(names)
	old := map[string]int{}
	for _, name := range names {
		value, err := h.setFrequencyFloor(name, floors[name].MinKHz)
		if err != nil {
			problem := fmt.Errorf("%s: %w", name, err)
			for previous, khz := range old {
				_, restore := h.setFrequencyFloor(previous, khz)
				problem = errors.Join(problem, restore)
			}
			return problem
		}
		old[name] = value
	}
	return nil
}

func runFrequencyGuard(args []string) error {
	fs := flag.NewFlagSet("frequency-guard", flag.ContinueOnError)
	config := fs.String("config", "/etc/vpp/system.json", "saved CPU frequency floors")
	sysfs := fs.String("sysfs", "/sys", "where sysfs is mounted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("frequency-guard 不接受位置参数")
	}
	cfg, err := loadConfig(*config)
	if err != nil {
		return err
	}
	return applyFrequencyFloors(host{sysfs: *sysfs}, cfg.FrequencyFloors)
}

// setFrequencyFloor changes only the lower bound. The existing governor and upper
// bound remain in control, so a worker can still scale above its cold-burst guard.
func (h host) setFrequencyFloor(policy string, khz int) (int, error) {
	if !strings.HasPrefix(policy, "policy") || strings.ContainsAny(policy, "/.") {
		return 0, fmt.Errorf("没有 %s", policy)
	}
	policies := h.policies()
	i := slices.IndexFunc(policies, func(p policyInfo) bool { return p.Name == policy })
	if i < 0 {
		return 0, fmt.Errorf("没有 %s", policy)
	}
	p := policies[i]
	if p.ScalingMinKHz <= 0 || p.ScalingMaxKHz <= 0 || p.MinKHz <= 0 {
		return 0, fmt.Errorf("%s 没有可设置的频率下限", policy)
	}
	if khz < p.MinKHz || khz > p.ScalingMaxKHz {
		return 0, fmt.Errorf("%s 的最低频率要在 %d 到 %d kHz 之间", policy, p.MinKHz, p.ScalingMaxKHz)
	}
	if len(p.Frequencies) > 0 && !slices.Contains(p.Frequencies, khz) {
		return 0, fmt.Errorf("%s 不支持 %d kHz", policy, khz)
	}
	path := filepath.Join(h.cpuDir(), "cpufreq", policy, "scaling_min_freq")
	if err := os.WriteFile(path, []byte(strconv.Itoa(khz)), 0o644); err != nil {
		return 0, err
	}
	if actual := waitFrequencyFloor(path, khz, frequencySettle); actual < khz {
		err := fmt.Errorf("%s 的最低频率写入后是 %d kHz，要求 %d kHz", policy, actual, khz)
		restore := os.WriteFile(path, []byte(strconv.Itoa(p.ScalingMinKHz)), 0o644)
		if restore == nil {
			if old := waitFrequencyFloor(path, p.ScalingMinKHz, frequencySettle); old < p.ScalingMinKHz {
				restore = fmt.Errorf("%s 恢复下限后是 %d kHz，要求 %d kHz", policy, old, p.ScalingMinKHz)
			}
		}
		return 0, errors.Join(err, restore)
	}
	return p.ScalingMinKHz, nil
}

// Zero disables the guard and restores the bound recorded before it was enabled.
func (s *Service) SetFrequencyFloor(policy string, khz int, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if khz < 0 {
		return nil, fmt.Errorf("最低频率不能为负数")
	}
	cfg := s.cfg.clone()
	before, configured := cfg.FrequencyFloors[policy]
	target := khz
	if khz == 0 {
		if !configured {
			return s.stateLocked(), nil
		}
		target = before.OriginalKHz
	}
	old, err := s.host.setFrequencyFloor(policy, target)
	if err != nil {
		return nil, err
	}
	if khz == 0 {
		delete(cfg.FrequencyFloors, policy)
	} else {
		if !configured {
			before.OriginalKHz = old
		}
		before.MinKHz = khz
		if cfg.FrequencyFloors == nil {
			cfg.FrequencyFloors = map[string]frequencyFloor{}
		}
		cfg.FrequencyFloors[policy] = before
	}
	if err := s.saveConfig(cfg); err != nil {
		_, restore := s.host.setFrequencyFloor(policy, old)
		return nil, errors.Join(err, restore)
	}
	log.Printf("audit: frequency floor %s %d kHz by %s", policy, khz, user)
	return s.stateLocked(), nil
}
