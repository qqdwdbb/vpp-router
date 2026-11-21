package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// CoreRow is one CPU core, or the "cpu" line for all of them.
type CoreRow struct {
	Name string  `json:"name"`
	Busy float64 `json:"busy"`
	MHz  float64 `json:"mhz"`
}

type TempRow struct {
	Key     string  `json:"key"`
	Name    string  `json:"name"`
	Celsius float64 `json:"celsius"`
}

// HostStatus describes the machine the monitor runs on, which is the one running VPP.
type HostStatus struct {
	CPU           float64   `json:"cpu"`
	Cores         []CoreRow `json:"cores"`
	MemTotal      float64   `json:"mem_total"`
	MemUsed       float64   `json:"mem_used"`
	SwapTotal     float64   `json:"swap_total"`
	SwapUsed      float64   `json:"swap_used"`
	DiskTotal     float64   `json:"disk_total"`
	DiskUsed      float64   `json:"disk_used"`
	Temps         []TempRow `json:"temps"`
	UptimeSeconds float64   `json:"uptime_seconds"`
}

type hostGauge struct {
	key   string
	value float64
}

type cpuTimes struct{ total, idle uint64 }

// hostReader reads procfs and sysfs under root, which is empty outside of tests.
type hostReader struct {
	root string
	prev map[string]cpuTimes
}

func (h *hostReader) file(path string) string {
	data, err := os.ReadFile(h.root + path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// read returns the current values, and the ones that keep a history. A source this kernel
// or board lacks is left empty. CPU use needs a previous reading, so it starts on the second.
func (h *hostReader) read() (HostStatus, []hostGauge) {
	var status HostStatus
	var gauges []hostGauge
	h.readCPU(&status, &gauges)
	h.readMemory(&status, &gauges)
	h.readTemperatures(&status, &gauges)
	h.readDisk(&status)
	if fields := strings.Fields(h.file("/proc/uptime")); len(fields) > 0 {
		status.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
	}
	return status, gauges
}

func parseCPUTimes(text string) ([]string, map[string]cpuTimes) {
	var names []string
	times := make(map[string]cpuTimes)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		var sample cpuTimes
		for i, field := range fields[1:] {
			if i == 8 { // guest time is already counted in user time
				break
			}
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				continue
			}
			sample.total += value
			if i == 3 || i == 4 { // idle and iowait
				sample.idle += value
			}
		}
		names = append(names, fields[0])
		times[fields[0]] = sample
	}
	return names, times
}

func (h *hostReader) readCPU(status *HostStatus, gauges *[]hostGauge) {
	names, times := parseCPUTimes(h.file("/proc/stat"))
	previous := h.prev
	h.prev = times
	for _, name := range names {
		before, seen := previous[name]
		now := times[name]
		if !seen || now.total <= before.total {
			continue
		}
		idle := float64(0)
		if now.idle > before.idle {
			idle = float64(now.idle - before.idle)
		}
		total := float64(now.total - before.total)
		busy := 100 * (total - idle) / total
		if busy < 0 {
			busy = 0
		}
		if name == "cpu" {
			status.CPU = busy
			*gauges = append(*gauges, hostGauge{"host/cpu/busy", busy})
			continue
		}
		row := CoreRow{Name: name, Busy: busy}
		if khz, err := strconv.ParseFloat(h.file("/sys/devices/system/cpu/"+name+"/cpufreq/scaling_cur_freq"), 64); err == nil {
			row.MHz = khz / 1000
		}
		status.Cores = append(status.Cores, row)
		*gauges = append(*gauges, hostGauge{"host/cpu/" + name + "/busy", busy})
	}
}

func (h *hostReader) readMemory(status *HostStatus, gauges *[]hostGauge) {
	values := make(map[string]float64)
	for _, line := range strings.Split(h.file("/proc/meminfo"), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if value, err := strconv.ParseFloat(fields[1], 64); err == nil {
				values[strings.TrimSuffix(fields[0], ":")] = value * 1024
			}
		}
	}
	if values["MemTotal"] == 0 {
		return
	}
	status.MemTotal = values["MemTotal"]
	status.MemUsed = values["MemTotal"] - values["MemAvailable"]
	status.SwapTotal = values["SwapTotal"]
	status.SwapUsed = values["SwapTotal"] - values["SwapFree"]
	*gauges = append(*gauges, hostGauge{"host/mem/used", status.MemUsed})
	if status.SwapTotal > 0 {
		*gauges = append(*gauges, hostGauge{"host/swap/used", status.SwapUsed})
	}
}

var hwmonSensor = regexp.MustCompile(`^(.*)/(temp\d+)_input$`)

// readTemperatures prefers thermal zones, and uses hwmon on machines that have none.
func (h *hostReader) readTemperatures(status *HostStatus, gauges *[]hostGauge) {
	add := func(key, name, milli string) {
		value, err := strconv.ParseFloat(milli, 64)
		if err != nil {
			return
		}
		celsius := value / 1000
		// Some sensors report placeholders for an absent probe.
		if celsius <= -40 || celsius >= 150 {
			return
		}
		status.Temps = append(status.Temps, TempRow{Key: "host/temp/" + key, Name: name, Celsius: celsius})
		*gauges = append(*gauges, hostGauge{"host/temp/" + key, celsius})
	}
	zones, _ := filepath.Glob(h.root + "/sys/class/thermal/thermal_zone*")
	sort.Strings(zones)
	for _, zone := range zones {
		relative := strings.TrimPrefix(zone, h.root)
		add(filepath.Base(zone), h.file(relative+"/type"), h.file(relative+"/temp"))
	}
	if len(status.Temps) > 0 {
		return
	}
	sensors, _ := filepath.Glob(h.root + "/sys/class/hwmon/hwmon*/temp*_input")
	sort.Strings(sensors)
	for _, sensor := range sensors {
		match := hwmonSensor.FindStringSubmatch(strings.TrimPrefix(sensor, h.root))
		if match == nil {
			continue
		}
		name := h.file(match[1] + "/name")
		if label := h.file(match[1] + "/" + match[2] + "_label"); label != "" {
			name = fmt.Sprintf("%s %s", name, label)
		}
		add(filepath.Base(match[1])+"_"+match[2], name, h.file(sensor[len(h.root):]))
	}
}

// readDisk reports the root filesystem the way df does, without the blocks kept for root.
func (h *hostReader) readDisk(status *HostStatus) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(h.root+"/", &stat); err != nil {
		return
	}
	size := float64(stat.Bsize)
	used := float64(stat.Blocks-stat.Bfree) * size
	status.DiskUsed = used
	status.DiskTotal = used + float64(stat.Bavail)*size
}
