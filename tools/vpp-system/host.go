package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The host's CPUs and their cpufreq policies, from sysfs.

type cpuInfo struct {
	ID       int    `json:"id"`
	Capacity int    `json:"capacity"` // cpu_capacity, 0 when the kernel has none (x86)
	MaxKHz   int    `json:"max_khz"`
	Policy   string `json:"policy"`
	Big      bool   `json:"big"` // the fastest kind on a big.LITTLE machine
}

type policyInfo struct {
	Name          string   `json:"name"`
	CPUs          []int    `json:"cpus"`
	Governor      string   `json:"governor"`
	Available     []string `json:"available"`
	CurKHz        int      `json:"cur_khz"`
	MinKHz        int      `json:"min_khz"`
	MaxKHz        int      `json:"max_khz"`
	ScalingMinKHz int      `json:"scaling_min_khz"`
	ScalingMaxKHz int      `json:"scaling_max_khz"`
	Frequencies   []int    `json:"frequencies"`
	Driver        string   `json:"driver"`
}

type host struct {
	sysfs    string // usually /sys
	proc     string // usually /proc
	addrs    func(ifname string) []string
	channels func(ifname string) int
}

func (h host) cpuDir() string { return filepath.Join(h.sysfs, "devices/system/cpu") }

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readInt(path string) int {
	n, _ := strconv.Atoi(readTrim(path))
	return n
}

// online is the CPUs Linux has online.
func (h host) online() ([]int, error) {
	text := readTrim(filepath.Join(h.cpuDir(), "online"))
	if text == "" {
		return nil, errors.New("读不到 " + filepath.Join(h.cpuDir(), "online"))
	}
	return parseCoreList(text)
}

func (h host) policies() []policyInfo {
	dirs, _ := filepath.Glob(filepath.Join(h.cpuDir(), "cpufreq/policy*"))
	var list []policyInfo
	for _, dir := range dirs {
		p := policyInfo{Name: filepath.Base(dir)}
		p.CPUs, _ = parseCoreList(strings.Join(strings.Fields(readTrim(filepath.Join(dir, "related_cpus"))), ","))
		p.Governor = readTrim(filepath.Join(dir, "scaling_governor"))
		p.Available = strings.Fields(readTrim(filepath.Join(dir, "scaling_available_governors")))
		p.CurKHz = readInt(filepath.Join(dir, "scaling_cur_freq"))
		p.MinKHz = readInt(filepath.Join(dir, "cpuinfo_min_freq"))
		p.MaxKHz = readInt(filepath.Join(dir, "cpuinfo_max_freq"))
		p.ScalingMinKHz = readInt(filepath.Join(dir, "scaling_min_freq"))
		p.ScalingMaxKHz = readInt(filepath.Join(dir, "scaling_max_freq"))
		for _, value := range strings.Fields(readTrim(filepath.Join(dir, "scaling_available_frequencies"))) {
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				p.Frequencies = append(p.Frequencies, n)
			}
		}
		slices.Sort(p.Frequencies)
		p.Driver = readTrim(filepath.Join(dir, "scaling_driver"))
		list = append(list, p)
	}
	slices.SortFunc(list, func(a, b policyInfo) int {
		x, _ := strconv.Atoi(strings.TrimPrefix(a.Name, "policy"))
		y, _ := strconv.Atoi(strings.TrimPrefix(b.Name, "policy"))
		return x - y
	})
	return list
}

func (h host) cpus(policies []policyInfo) ([]cpuInfo, error) {
	ids, err := h.online()
	if err != nil {
		return nil, err
	}
	var list []cpuInfo
	top := 0
	kinds := map[int]bool{}
	for _, id := range ids {
		c := cpuInfo{ID: id, Capacity: readInt(filepath.Join(h.cpuDir(), fmt.Sprintf("cpu%d/cpu_capacity", id)))}
		for _, p := range policies {
			if slices.Contains(p.CPUs, id) {
				c.Policy, c.MaxKHz = p.Name, p.MaxKHz
			}
		}
		key := c.Capacity
		if key == 0 {
			key = c.MaxKHz
		}
		kinds[key] = true
		top = max(top, key)
		list = append(list, c)
	}
	if len(kinds) > 1 {
		for i := range list {
			key := list[i].Capacity
			if key == 0 {
				key = list[i].MaxKHz
			}
			list[i].Big = key == top
		}
	}
	return list, nil
}

func (h host) setGovernor(policy, governor string) error {
	if !strings.HasPrefix(policy, "policy") || strings.ContainsAny(policy, "/.") {
		return fmt.Errorf("没有 %s", policy)
	}
	dir := filepath.Join(h.cpuDir(), "cpufreq", policy)
	available := strings.Fields(readTrim(filepath.Join(dir, "scaling_available_governors")))
	if !slices.Contains(available, governor) {
		return fmt.Errorf("%s 不支持调速器 %q，可选：%s", policy, governor, strings.Join(available, " "))
	}
	if err := os.WriteFile(filepath.Join(dir, "scaling_governor"), []byte(governor), 0o644); err != nil {
		return fmt.Errorf("设置 %s 的调速器：%w", policy, err)
	}
	if now := readTrim(filepath.Join(dir, "scaling_governor")); now != governor {
		return fmt.Errorf("%s 的调速器写入后仍是 %s", policy, now)
	}
	return nil
}
