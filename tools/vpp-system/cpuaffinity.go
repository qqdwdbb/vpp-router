package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Only installations that opt into worker isolation (SYSTEM_CPUS in router.env) are managed.
// These files join the same persisted confirmation/rollback transaction as the startup file.
func (s *Service) workerCPUFiles(workers []int, files map[string]string) error {
	if s.opts.RouterEnv == "" || s.opts.CPUAffinityFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.opts.RouterEnv)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	env := parseRouterEnv(string(data))
	if _, managed := env.vars["SYSTEM_CPUS"]; !managed {
		return nil
	}
	online, err := s.host.online()
	if err != nil {
		return err
	}
	var system []int
	for _, cpu := range online {
		if !slices.Contains(workers, cpu) {
			system = append(system, cpu)
		}
	}
	if len(system) == 0 {
		return fmt.Errorf("没有留给系统的 CPU")
	}
	mask := formatCoreList(system)
	envMask := mask
	if len(workers) == 0 {
		envMask = ""
	}
	assignment := regexp.MustCompile(`(?m)^[\t ]*SYSTEM_CPUS=.*$`)
	files[s.opts.RouterEnv] = assignment.ReplaceAllString(env.text, "SYSTEM_CPUS="+envMask)
	files[s.opts.CPUAffinityFile] = "# 由 vpp-router 管理：其他进程不用 worker 的 CPU\n[Manager]\nCPUAffinity=" + mask + "\n"
	// VPP must be able to pin its threads to the selected CPUs, including after workers are removed.
	unit, err := os.ReadFile(s.opts.UnitFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(unit), "\n")
	section := ""
	var out []string
	found := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			section = trim
			out = append(out, line)
			if section == "[Service]" {
				out = append(out, "CPUAffinity="+formatCoreList(online))
				found = true
			}
			continue
		}
		key, _, _ := strings.Cut(trim, "=")
		if section == "[Service]" && strings.TrimSpace(key) == "CPUAffinity" {
			continue
		}
		out = append(out, line)
	}
	if !found {
		return fmt.Errorf("%s 缺少 [Service]", s.opts.UnitFile)
	}
	files[s.opts.UnitFile] = strings.Join(out, "\n")
	return nil
}
