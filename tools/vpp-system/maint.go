package main

// The panel's maintenance page: the deployment's systemd units (state, start, stop, restart,
// and rebooting the host), their journal, network tests from Linux or from inside VPP, and a
// download of the configuration.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxLogLines      = 2000
	maxDownloadLines = 50000
	// grepScan is how many lines are read to find the last matches of a keyword.
	grepScan       = 20000
	testTimeout    = 40 * time.Second
	maxBackupFile  = 16 << 20
	delayedActions = 2 * time.Second
)

// Maint serves the maintenance page.
type Maint struct {
	s        *Service
	unitDir  string
	extra    []string
	backup   []string
	selfUnit string

	// run runs a command and returns its output; systemctl and journalctl go through it.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)

	testing sync.Mutex
}

func NewMaint(s *Service, unitDir string, extra, backup []string) *Maint {
	m := &Maint{s: s, unitDir: unitDir, extra: extra, backup: backup, run: runCommand}
	m.selfUnit = unitOfPID("self")
	return m
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if text := strings.TrimSpace(stderr.String()); text != "" {
			return out, fmt.Errorf("%s: %s", name, text)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// unitOfPID is the systemd service a process runs in, from its cgroup.
func unitOfPID(pid string) string {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return ""
	}
	return unitFromCgroup(string(data))
}

func unitFromCgroup(text string) string {
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, part := range slices.Backward(strings.Split(parts[2], "/")) {
			if strings.HasSuffix(part, ".service") {
				return part
			}
		}
	}
	return ""
}

// Unit is one systemd service on the page.
type Unit struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Enabled     string `json:"enabled"`
	Since       int64  `json:"since,omitempty"` // unix seconds the unit entered its state
	PID         int    `json:"pid,omitempty"`
	Memory      int64  `json:"memory,omitempty"`
	Restarts    int    `json:"restarts"`
	Result      string `json:"result"`
	// Related units belong to the router: VPP, what depends on it, and what mentions VPP.
	Related bool `json:"related"`
	// Role is "vpp", "panel" (serves this page) or "self" (vpp-system); these can be
	// restarted but not stopped from the page.
	Role string `json:"role,omitempty"`
}

// UnitsView is the services section.
type UnitsView struct {
	Units    []Unit `json:"units"`
	VPPUnit  string `json:"vpp_unit"`
	Pending  string `json:"pending,omitempty"` // why restarting VPP or rebooting is refused now
	BootTime int64  `json:"boot_time"`
	// Backup is what the configuration download holds besides the unit files.
	Backup []string `json:"backup"`
}

// unitNames are the units to show: unit files the administrator installed (regular files in
// the unit directory, not templates), VPP's unit and -units.
func (m *Maint) unitNames() []string {
	names := map[string]bool{}
	if entries, err := os.ReadDir(m.unitDir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.Type().IsRegular() || !strings.HasSuffix(name, ".service") || strings.Contains(name, "@") {
				continue
			}
			names[name] = true
		}
	}
	for _, name := range append([]string{m.s.opts.VPPUnit}, m.extra...) {
		if name == "" {
			continue
		}
		if !strings.Contains(name, ".") {
			name += ".service"
		}
		names[name] = true
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	slices.Sort(list)
	return list
}

var unitProperties = []string{"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState",
	"StateChangeTimestamp", "MainPID", "MemoryCurrent", "NRestarts", "Result", "FragmentPath",
	"After", "Requires", "Wants", "BindsTo", "PartOf", "Requisite"}

// parseShow splits `systemctl show` output into one map per unit.
func parseShow(text string) []map[string]string {
	var list []map[string]string
	current := map[string]string{}
	flush := func() {
		if len(current) > 0 {
			list = append(list, current)
			current = map[string]string{}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			current[key] = value
		}
	}
	flush()
	return list
}

func parseUnixTimestamp(value string) int64 {
	n, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(value), "@"), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (m *Maint) units(ctx context.Context, panel string) (*UnitsView, error) {
	names := m.unitNames()
	view := &UnitsView{Units: []Unit{}, VPPUnit: m.s.opts.VPPUnit, BootTime: bootTime(), Backup: slices.Clone(m.backup)}
	m.s.mu.Lock()
	if err := m.s.otherPending(); err != nil {
		view.Pending = err.Error()
	}
	m.s.mu.Unlock()
	if len(names) == 0 {
		return view, nil
	}
	args := []string{"show", "--timestamp=unix", "--property=" + strings.Join(unitProperties, ","), "--"}
	out, err := m.run(ctx, "systemctl", append(args, names...)...)
	if err != nil && len(out) == 0 {
		return nil, err
	}
	for _, p := range parseShow(string(out)) {
		if p["LoadState"] != "loaded" {
			continue
		}
		u := Unit{
			Name: p["Id"], Description: p["Description"], Active: p["ActiveState"], Sub: p["SubState"],
			Enabled: p["UnitFileState"], Since: parseUnixTimestamp(p["StateChangeTimestamp"]), Result: p["Result"],
		}
		u.PID, _ = strconv.Atoi(p["MainPID"])
		u.Memory, _ = strconv.ParseInt(p["MemoryCurrent"], 10, 64) // [not set] is a huge number or text
		if u.Memory < 0 || u.Memory > 1<<50 {
			u.Memory = 0
		}
		u.Restarts, _ = strconv.Atoi(p["NRestarts"])
		switch u.Name {
		case m.s.opts.VPPUnit:
			u.Role = "vpp"
		case panel:
			u.Role = "panel"
		case m.selfUnit:
			u.Role = "self"
		}
		u.Related = u.Role != "" || m.relatedUnit(p)
		view.Units = append(view.Units, u)
	}
	return view, nil
}

// relatedUnit says if a unit belongs to the router: it is ordered after or needs VPP's unit,
// or its unit file mentions VPP (the router's programs, /etc/vpp, VPP's sockets) or runs
// gate-admin, the panel's helper for Gate, whose unit names neither.
func (m *Maint) relatedUnit(p map[string]string) bool {
	if vpp := m.s.opts.VPPUnit; vpp != "" {
		for _, key := range []string{"After", "Requires", "Wants", "BindsTo", "PartOf", "Requisite"} {
			if slices.Contains(strings.Fields(p[key]), vpp) {
				return true
			}
		}
	}
	if path := p["FragmentPath"]; path != "" {
		if data, err := os.ReadFile(path); err == nil && (bytes.Contains(bytes.ToLower(data), []byte("vpp")) || bytes.Contains(data, []byte("/gate-admin"))) {
			return true
		}
	}
	return false
}

func bootTime() int64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			return n
		}
	}
	return 0
}

// UnitAction starts, stops or restarts a unit, or reboots the host (action "reboot").
func (m *Maint) UnitAction(ctx context.Context, name, action, panel, user string) error {
	if action == "reboot" {
		m.s.mu.Lock()
		err := m.s.otherPending()
		m.s.mu.Unlock()
		if err != nil {
			return err
		}
		log.Printf("audit: %s: reboot the host", user)
		return m.delayed(ctx, "reboot")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return errors.New("不支持的操作")
	}
	view, err := m.units(ctx, panel)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(view.Units, func(u Unit) bool { return u.Name == name })
	if i < 0 {
		return fmt.Errorf("没有服务 %s", name)
	}
	unit := view.Units[i]
	if unit.Role != "" && action == "stop" {
		return errors.New("这个服务停止后面板无法再启动它，只能重启")
	}
	if unit.Role == "vpp" && view.Pending != "" {
		return fmt.Errorf("%s，确认或恢复后再重启 VPP", view.Pending)
	}
	log.Printf("audit: %s: %s %s", user, action, name)
	// Restarting this program or the panel ends the request before it is answered.
	if unit.Role == "self" || unit.Role == "panel" {
		return m.delayed(ctx, "restart", name)
	}
	_, err = m.run(ctx, "systemctl", action, "--no-block", "--", name)
	return err
}

// delayed runs systemctl a moment later from a transient timer, after the reply is sent.
func (m *Maint) delayed(ctx context.Context, args ...string) error {
	unit := fmt.Sprintf("vpp-maint-%d", time.Now().UnixNano())
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	run := []string{"--unit", unit, "--collect", "--quiet", "--on-active", fmt.Sprintf("%dms", delayedActions.Milliseconds()),
		"--timer-property=AccuracySec=100ms", systemctl}
	_, err = m.run(ctx, "systemd-run", append(run, args...)...)
	return err
}

// LogEntry is one journal line.
type LogEntry struct {
	Time     int64  `json:"time"` // microseconds
	Source   string `json:"source"`
	Priority int    `json:"priority"`
	Message  string `json:"message"`
}

// LogsView is a page of the journal. Cursor continues it.
type LogsView struct {
	Entries []LogEntry `json:"entries"`
	Cursor  string     `json:"cursor"`
	// Truncated says that more lines matched than were returned.
	Truncated bool   `json:"truncated"`
	Text      string `json:"text,omitempty"` // VPP's show logging
}

// LogQuery selects journal lines.
type LogQuery struct {
	Unit     string // a unit on the page, "kernel", or "" for everything
	Lines    int
	Since    int64 // unix seconds, 0 for no limit
	Boot     bool  // only this boot
	Priority int   // most severe level to show, -1 for all
	Grep     string
	After    string // continue from this cursor
}

func parseLogQuery(values url.Values) (LogQuery, error) {
	q := LogQuery{Unit: values.Get("unit"), Lines: 300, Priority: -1, Grep: values.Get("grep"), After: values.Get("after"), Boot: values.Get("boot") == "1"}
	if v := values.Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return q, errors.New("行数不对")
		}
		q.Lines = n
	}
	if v := values.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return q, errors.New("起始时间不对")
		}
		q.Since = n
	}
	if v := values.Get("priority"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 7 {
			return q, errors.New("级别不对")
		}
		q.Priority = n
	}
	if len(q.Grep) > 200 {
		return q, errors.New("关键词太长")
	}
	return q, nil
}

func (m *Maint) journalArgs(ctx context.Context, q LogQuery, limit int, output string) ([]string, error) {
	args := []string{"--no-pager", "--quiet", "-o", output}
	switch q.Unit {
	case "":
	case "kernel":
		args = append(args, "--dmesg")
	default:
		view, err := m.units(ctx, "")
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(view.Units, func(u Unit) bool { return u.Name == q.Unit }) {
			return nil, fmt.Errorf("没有服务 %s", q.Unit)
		}
		args = append(args, "--unit", q.Unit)
	}
	if q.Boot {
		args = append(args, "--boot")
	}
	if q.Since > 0 {
		args = append(args, "--since", "@"+strconv.FormatInt(q.Since, 10))
	}
	if q.Priority >= 0 {
		args = append(args, "--priority", strconv.Itoa(q.Priority))
	}
	if q.After != "" {
		args = append(args, "--after-cursor", q.After)
	}
	n := limit
	if q.Grep != "" {
		n = max(limit, grepScan)
	}
	return append(args, "--lines", strconv.Itoa(n)), nil
}

func (m *Maint) Logs(ctx context.Context, q LogQuery) (*LogsView, error) {
	if q.Unit == "vpp:logging" {
		return m.vppLogging(q)
	}
	limit := min(q.Lines, maxLogLines)
	args, err := m.journalArgs(ctx, q, limit, "json")
	if err != nil {
		return nil, err
	}
	out, err := m.run(ctx, "journalctl", args...)
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return parseJournal(out, q, limit), nil
}

// parseJournal reads journalctl's JSON lines, keeping the last limit that match.
func parseJournal(out []byte, q LogQuery, limit int) *LogsView {
	view := &LogsView{Entries: []LogEntry{}, Cursor: q.After}
	grep := strings.ToLower(q.Grep)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		var raw map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &raw) != nil {
			continue
		}
		field := func(key string) string { return journalString(raw[key]) }
		if cursor := field("__CURSOR"); cursor != "" {
			view.Cursor = cursor
		}
		message := field("MESSAGE")
		if grep != "" && !strings.Contains(strings.ToLower(message), grep) {
			continue
		}
		e := LogEntry{Message: message, Priority: 6}
		e.Time, _ = strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64)
		if p, err := strconv.Atoi(field("PRIORITY")); err == nil {
			e.Priority = p
		}
		e.Source = field("SYSLOG_IDENTIFIER")
		if e.Source == "" {
			e.Source = strings.TrimSuffix(field("_SYSTEMD_UNIT"), ".service")
		}
		if e.Source == "" && field("_TRANSPORT") == "kernel" {
			e.Source = "kernel"
		}
		view.Entries = append(view.Entries, e)
	}
	if len(view.Entries) > limit {
		view.Entries = slices.Clone(view.Entries[len(view.Entries)-limit:])
		view.Truncated = true
	}
	return view
}

// journalString reads a journal field: a string, or an array of bytes when it is not UTF-8.
func journalString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, n := range ints {
			b = append(b, byte(n))
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	return ""
}

func (m *Maint) vppLogging(q LogQuery) (*LogsView, error) {
	v, err := m.s.dial()
	if err != nil {
		return nil, fmt.Errorf("VPP 没有应答：%w", err)
	}
	defer v.Close()
	text, err := v.CLI("show logging")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if q.Grep != "" {
		grep := strings.ToLower(q.Grep)
		lines = slices.DeleteFunc(lines, func(line string) bool { return !strings.Contains(strings.ToLower(line), grep) })
	}
	view := &LogsView{Entries: []LogEntry{}}
	if limit := min(q.Lines, maxLogLines); len(lines) > limit {
		lines = lines[len(lines)-limit:]
		view.Truncated = true
	}
	view.Text = strings.Join(lines, "\n")
	return view, nil
}

// LogsText writes the selected journal lines as text, for download.
func (m *Maint) LogsText(ctx context.Context, w http.ResponseWriter, q LogQuery) error {
	if q.Unit == "vpp:logging" {
		view, err := m.vppLogging(LogQuery{Lines: maxLogLines, Grep: q.Grep})
		if err != nil {
			return err
		}
		m.attachment(w, "vpp-logging", "txt", "text/plain; charset=utf-8")
		_, err = io.WriteString(w, view.Text+"\n")
		return err
	}
	q.After = ""
	limit := min(max(q.Lines, 1), maxDownloadLines)
	args, err := m.journalArgs(ctx, q, limit, "short-iso")
	if err != nil {
		return err
	}
	out, err := m.run(ctx, "journalctl", args...)
	if err != nil && len(out) == 0 {
		return err
	}
	if q.Grep != "" {
		grep := strings.ToLower(q.Grep)
		lines := strings.Split(string(out), "\n")
		lines = slices.DeleteFunc(lines, func(line string) bool { return !strings.Contains(strings.ToLower(line), grep) })
		if len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}
		out = []byte(strings.Join(lines, "\n") + "\n")
	}
	name := strings.TrimSuffix(q.Unit, ".service")
	if name == "" {
		name = "journal"
	}
	m.attachment(w, "log-"+name, "txt", "text/plain; charset=utf-8")
	_, err = w.Write(out)
	return err
}

func (m *Maint) attachment(w http.ResponseWriter, name, ext, contentType string) {
	host, _ := os.Hostname()
	file := fmt.Sprintf("%s-%s-%s.%s", safeName(host), safeName(name), time.Now().Format("20060102-150405"), ext)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	w.Header().Set("Cache-Control", "no-store")
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	if s = strings.Trim(unsafeName.ReplaceAllString(s, "_"), "_"); s == "" {
		return "host"
	}
	return s
}

// TestRequest is one network test.
type TestRequest struct {
	Kind      string `json:"kind"`      // ping, traceroute, dns, http
	Target    string `json:"target"`    // host or address; a URL for http
	From      string `json:"from"`      // linux or vpp
	Interface string `json:"interface"` // Linux device or VPP interface, empty for the routing table's choice
	Family    int    `json:"family"`    // 0, 4 or 6
	Count     int    `json:"count"`
	Server    string `json:"server"` // DNS server, empty for the system's
	Type      string `json:"type"`   // DNS record type
}

// TestResult is a finished test.
type TestResult struct {
	Command  string  `json:"command"`
	Output   string  `json:"output"`
	OK       bool    `json:"ok"`
	Seconds  float64 `json:"seconds"`
	TimedOut bool    `json:"timed_out,omitempty"`
}

// TestSources lists what the tests can be sent from.
type TestSources struct {
	Linux    []string `json:"linux"`
	VPP      []string `json:"vpp"`
	VPPError string   `json:"vpp_error,omitempty"`
	// Traceroute is the tool found: traceroute (the Linux one, or busybox), inetutils
	// (GNU inetutils' traceroute: IPv4 only, no device), tracepath, or empty for none.
	Traceroute string `json:"traceroute"`
	// TraceInterface says the tool can leave through a chosen device.
	TraceInterface bool `json:"trace_interface"`
}

// traceTools finds the route tracing tools: which traceroute, and whether tracepath is there.
func traceTools() (traceroute string, tracepath bool) {
	if _, err := exec.LookPath("traceroute"); err == nil {
		traceroute = "traceroute"
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, _ := exec.CommandContext(ctx, "traceroute", "--version").CombinedOutput()
		cancel()
		if bytes.Contains(bytes.ToLower(out), []byte("inetutils")) {
			traceroute = "inetutils"
		}
	}
	_, err := exec.LookPath("tracepath")
	return traceroute, err == nil
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?\.?$`)

// checkHost accepts an address or a host name; never something a command reads as an option.
func checkHost(target string) error {
	if _, err := netip.ParseAddr(target); err == nil {
		return nil
	}
	if len(target) > 253 || !hostPattern.MatchString(target) {
		return errors.New("目标要是 IP 地址或域名")
	}
	return nil
}

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,63}$`)

func (m *Maint) Sources(ctx context.Context) *TestSources {
	src := &TestSources{Linux: []string{}, VPP: []string{}}
	if list, err := net.Interfaces(); err == nil {
		for _, i := range list {
			src.Linux = append(src.Linux, i.Name)
		}
	}
	if v, err := m.s.dial(); err != nil {
		src.VPPError = "VPP 没有应答"
	} else {
		text, err := v.CLI("show interface")
		v.Close()
		if err != nil {
			src.VPPError = err.Error()
		} else {
			src.VPP = parseInterfaceNames(text)
		}
	}
	traceroute, tracepath := traceTools()
	src.Traceroute = traceroute
	if traceroute == "" && tracepath {
		src.Traceroute = "tracepath"
	}
	src.TraceInterface = traceroute == "traceroute"
	return src
}

// parseInterfaceNames reads the names from `show interface`, skipping local0.
func parseInterfaceNames(text string) []string {
	names := []string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Name" || fields[0] == "local0" {
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

func (m *Maint) Test(ctx context.Context, q TestRequest, user string) (*TestResult, error) {
	if !m.testing.TryLock() {
		return nil, errors.New("已有测试在运行，等它结束")
	}
	defer m.testing.Unlock()
	q.Target = strings.TrimSpace(q.Target)
	if q.Interface != "" && !interfacePattern.MatchString(q.Interface) {
		return nil, errors.New("接口名不对")
	}
	if q.Family != 0 && q.Family != 4 && q.Family != 6 {
		return nil, errors.New("地址族不对")
	}
	if q.Count <= 0 {
		q.Count = 4
	}
	q.Count = min(q.Count, 20)
	if q.Kind == "http" {
		if _, err := httpURL(q.Target); err != nil {
			return nil, err
		}
	} else if err := checkHost(q.Target); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	log.Printf("audit: %s: test %s %q from %q %q", user, q.Kind, q.Target, q.From, q.Interface)
	start := time.Now()
	var result *TestResult
	var err error
	switch {
	case q.Kind == "http":
		result, err = m.testHTTP(ctx, q)
	case q.Kind == "dns":
		result, err = m.testDNS(ctx, q)
	case q.From == "vpp" && q.Kind == "ping":
		result, err = m.vppPing(ctx, q)
	case q.From == "vpp":
		return nil, errors.New("VPP 里只能 ping")
	case q.Kind == "ping" || q.Kind == "traceroute":
		result, err = m.linuxCommand(ctx, q)
	default:
		return nil, errors.New("不支持的测试")
	}
	if err != nil {
		return nil, err
	}
	result.Seconds = time.Since(start).Seconds()
	result.TimedOut = ctx.Err() == context.DeadlineExceeded
	return result, nil
}

func (m *Maint) linuxCommand(ctx context.Context, q TestRequest) (*TestResult, error) {
	var name string
	var args []string
	family := func() {
		if q.Family != 0 {
			args = append(args, "-"+strconv.Itoa(q.Family))
		}
	}
	if q.Kind == "ping" {
		name = "ping"
		args = []string{"-n", "-c", strconv.Itoa(q.Count), "-i", "0.5", "-W", "2"}
		family()
		if q.Interface != "" {
			args = append(args, "-I", q.Interface)
		}
	} else {
		traceroute, tracepath := traceTools()
		switch {
		case traceroute == "traceroute":
			name = "traceroute"
			args = []string{"-n", "-w", "2", "-q", "1", "-m", "20"}
			family()
			if q.Interface != "" {
				args = append(args, "-i", q.Interface)
			}
		case traceroute == "" && !tracepath:
			return nil, errors.New("主机上没有 traceroute 或 tracepath")
		case q.Interface != "":
			return nil, errors.New("主机上的路由跟踪工具不能指定接口，装 Linux 的 traceroute 才行")
		case traceroute == "inetutils" && q.Family != 6:
			// GNU inetutils: numeric by default, no -n, no --, IPv4 only.
			name = "traceroute"
			args = []string{"-w", "2", "-q", "1", "-m", "20"}
		case tracepath:
			name = "tracepath"
			args = []string{"-n", "-m", "20"}
			family()
		default:
			return nil, errors.New("主机的 traceroute（GNU inetutils）只支持 IPv4")
		}
	}
	// The target was checked not to start with "-", as not every tool takes "--".
	if name == "ping" || (name == "traceroute" && len(args) > 0 && args[0] == "-n") {
		args = append(args, "--")
	}
	args = append(args, q.Target)
	command := append([]string{name}, args...)
	if name != "ping" {
		// Route tracing can run into the time limit; it leaves something to show only when
		// its output is line buffered, as tracepath buffers it when it is not a terminal.
		if stdbuf, err := exec.LookPath("stdbuf"); err == nil {
			command = append([]string{stdbuf, "-oL"}, command...)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, testTimeout-5*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		out = append(out, []byte("\n（到时间上限，停止）\n")...)
	}
	result := &TestResult{Command: name + " " + strings.Join(args, " "), Output: string(out), OK: err == nil}
	if err != nil && len(out) == 0 {
		result.Output = err.Error()
	}
	return result, nil
}

func (m *Maint) vppPing(ctx context.Context, q TestRequest) (*TestResult, error) {
	addr, note, err := resolveOne(ctx, q.Target, q.Family)
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("ping %s repeat %d interval 0.5", addr, q.Count)
	if q.Interface != "" {
		command += " source " + q.Interface
	}
	v, err := m.s.dial()
	if err != nil {
		return nil, fmt.Errorf("VPP 没有应答：%w", err)
	}
	defer v.Close()
	out, err := v.CLI(command)
	if err != nil {
		return nil, err
	}
	ok := strings.Contains(out, "bytes from") || regexp.MustCompile(`[1-9]\d* received`).MatchString(out)
	return &TestResult{Command: "vppctl " + command, Output: note + out, OK: ok}, nil
}

// resolveOne turns a host name into one address, for tests that need an address.
func resolveOne(ctx context.Context, target string, family int) (netip.Addr, string, error) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.Unmap(), "", nil
	}
	network := "ip"
	if family != 0 {
		network = "ip" + strconv.Itoa(family)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, target)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("解析 %s 失败：%w", target, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, "", fmt.Errorf("%s 没有地址", target)
	}
	addr := addrs[0].Unmap()
	return addr, fmt.Sprintf("%s 解析为 %s（主机的 DNS）\n", target, addr), nil
}

func (m *Maint) testDNS(ctx context.Context, q TestRequest) (*TestResult, error) {
	kind := strings.ToUpper(q.Type)
	if kind == "" {
		kind = "A"
	}
	resolver := net.DefaultResolver
	server := "系统 DNS"
	if q.Server != "" {
		addrPort, err := parseServer(q.Server)
		if err != nil {
			return nil, err
		}
		server = addrPort.String()
		dialer := &net.Dialer{Timeout: 5 * time.Second, Control: bindControl(q.Interface)}
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, server)
		}}
	} else if q.Interface != "" {
		return nil, errors.New("指定接口时要填 DNS 服务器")
	}
	start := time.Now()
	var lines []string
	var err error
	switch kind {
	case "A", "AAAA":
		var addrs []netip.Addr
		addrs, err = resolver.LookupNetIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[kind], q.Target)
		for _, a := range addrs {
			lines = append(lines, a.Unmap().String())
		}
	case "CNAME":
		var name string
		name, err = resolver.LookupCNAME(ctx, q.Target)
		lines = append(lines, name)
	case "MX":
		var list []*net.MX
		list, err = resolver.LookupMX(ctx, q.Target)
		for _, mx := range list {
			lines = append(lines, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
	case "TXT":
		lines, err = resolver.LookupTXT(ctx, q.Target)
	case "NS":
		var list []*net.NS
		list, err = resolver.LookupNS(ctx, q.Target)
		for _, ns := range list {
			lines = append(lines, ns.Host)
		}
	default:
		return nil, errors.New("不支持的记录类型")
	}
	elapsed := time.Since(start)
	var out strings.Builder
	fmt.Fprintf(&out, "服务器 %s，%s 记录，用时 %.1f ms\n", server, kind, float64(elapsed.Microseconds())/1000)
	if err != nil {
		// Go names the system's server in the error even when another one was asked.
		var dnsErr *net.DNSError
		switch {
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			out.WriteString("失败：没有这个域名或没有这类记录\n")
		case errors.As(err, &dnsErr):
			fmt.Fprintf(&out, "失败：%s\n", dnsErr.Err)
		default:
			fmt.Fprintf(&out, "失败：%v\n", err)
		}
	} else if len(lines) == 0 {
		out.WriteString("没有记录\n")
	}
	for _, line := range lines {
		out.WriteString(line + "\n")
	}
	command := "dns " + kind + " " + q.Target
	if q.Server != "" {
		command += " @" + server
	}
	return &TestResult{Command: command, Output: out.String(), OK: err == nil && len(lines) > 0}, nil
}

func parseServer(text string) (netip.AddrPort, error) {
	text = strings.TrimSpace(text)
	if ap, err := netip.ParseAddrPort(text); err == nil {
		return ap, nil
	}
	if addr, err := netip.ParseAddr(strings.Trim(text, "[]")); err == nil {
		return netip.AddrPortFrom(addr, 53), nil
	}
	return netip.AddrPort{}, errors.New("DNS 服务器要写成 IP 或 IP:端口")
}

// httpURL is an http or https URL; one with no scheme gets https.
func httpURL(target string) (*url.URL, error) {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("地址要是 http:// 或 https:// 开头的网址")
	}
	if err := checkHost(u.Hostname()); err != nil {
		return nil, err
	}
	return u, nil
}

func (m *Maint) testHTTP(ctx context.Context, q TestRequest) (*TestResult, error) {
	u, err := httpURL(q.Target)
	if err != nil {
		return nil, err
	}
	network := "tcp"
	if q.Family != 0 {
		network += strconv.Itoa(q.Family)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: bindControl(q.Interface)}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		Proxy:               nil,
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var out strings.Builder
	start := time.Now()
	mark := func(what string) {
		fmt.Fprintf(&out, "%7.1f ms  %s\n", float64(time.Since(start).Microseconds())/1000, what)
	}
	trace := &httptrace.ClientTrace{
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				mark("解析失败：" + info.Err.Error())
				return
			}
			var addrs []string
			for _, a := range info.Addrs {
				addrs = append(addrs, a.IP.String())
			}
			mark("解析为 " + strings.Join(addrs, " "))
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				mark("连接 " + addr + " 失败：" + err.Error())
			} else {
				mark("已连接 " + addr)
			}
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				mark("TLS 失败：" + err.Error())
				return
			}
			detail := tls.VersionName(state.Version)
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				detail += fmt.Sprintf("，证书 %s，%s 到期", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
			}
			mark("TLS 完成，" + detail)
		},
		GotFirstResponseByte: func() { mark("收到第一个字节") },
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "vpp-system-test")
	response, err := client.Do(request)
	ok := false
	if err != nil {
		mark("失败：" + err.Error())
	} else {
		n, _ := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		mark(fmt.Sprintf("完成，%s，读取 %d 字节", response.Status, n))
		if loc := response.Header.Get("Location"); loc != "" {
			fmt.Fprintf(&out, "跳转到 %s\n", loc)
		}
		if server := response.Header.Get("Server"); server != "" {
			fmt.Fprintf(&out, "Server: %s\n", server)
		}
		ok = response.StatusCode < 500
	}
	command := "GET " + u.String()
	if q.Interface != "" {
		command += " via " + q.Interface
	}
	return &TestResult{Command: command, Output: out.String(), OK: ok}, nil
}

// Backup writes the configuration as a gzipped tar: -backup's paths and the unit files of
// the router's units with their drop-ins.
func (m *Maint) Backup(ctx context.Context, w http.ResponseWriter, panel, user string) error {
	paths := slices.Clone(m.backup)
	if view, err := m.units(ctx, panel); err == nil {
		for _, u := range view.Units {
			if !u.Related {
				continue
			}
			paths = append(paths, filepath.Join(m.unitDir, u.Name), filepath.Join(m.unitDir, u.Name+".d"))
		}
	}
	log.Printf("audit: %s: download the configuration", user)
	m.attachment(w, "config", "tar.gz", "application/gzip")
	return writeBackup(w, paths, time.Now())
}

func writeBackup(w io.Writer, paths []string, now time.Time) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	var manifest strings.Builder
	host, _ := os.Hostname()
	fmt.Fprintf(&manifest, "host %s\ntime %s\n\n", host, now.Format(time.RFC3339))
	seen := map[string]bool{}
	for _, root := range paths {
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || seen[path] {
				return nil
			}
			seen[path] = true
			info, err := d.Info()
			if err != nil {
				return nil
			}
			name := strings.TrimPrefix(path, "/")
			switch {
			case d.IsDir():
				return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: int64(info.Mode().Perm()), ModTime: info.ModTime()})
			case info.Mode()&fs.ModeSymlink != 0:
				link, err := os.Readlink(path)
				if err != nil {
					return nil
				}
				fmt.Fprintf(&manifest, "%s -> %s\n", path, link)
				return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: link, ModTime: info.ModTime()})
			case !info.Mode().IsRegular():
				return nil
			case info.Size() > maxBackupFile:
				fmt.Fprintf(&manifest, "%s skipped, %d bytes\n", path, info.Size())
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(&manifest, "%s unreadable: %v\n", path, err)
				return nil
			}
			fmt.Fprintf(&manifest, "%s %d\n", path, len(data))
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: int64(info.Mode().Perm()), Size: int64(len(data)), ModTime: info.ModTime()}); err != nil {
				return err
			}
			_, err = tw.Write(data)
			return err
		})
	}
	text := manifest.String()
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "MANIFEST.txt", Mode: 0o644, Size: int64(len(text)), ModTime: now}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, text); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// panelUnit is the unit of the process on the other end of the request's connection.
func panelUnit(r *http.Request) string {
	conn, _ := r.Context().Value(connKey{}).(*net.UnixConn)
	if conn == nil {
		return ""
	}
	pid := peerPID(conn)
	if pid <= 0 {
		return ""
	}
	return unitOfPID(strconv.Itoa(pid))
}

type connKey struct{}

// routes adds the maintenance API to the mux.
func (m *Maint) routes(mux *http.ServeMux, reply func(http.ResponseWriter, any, error), user func(*http.Request) string) {
	mux.HandleFunc("GET /system/maint/units", func(w http.ResponseWriter, r *http.Request) {
		view, err := m.units(r.Context(), panelUnit(r))
		reply(w, view, err)
	})
	mux.HandleFunc("POST /system/maint/units", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Unit   string `json:"unit"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&q); err != nil {
			reply(w, nil, errors.New("bad request"))
			return
		}
		panel := panelUnit(r)
		if err := m.UnitAction(r.Context(), q.Unit, q.Action, panel, user(r)); err != nil {
			reply(w, nil, err)
			return
		}
		view, err := m.units(r.Context(), panel)
		reply(w, view, err)
	})
	mux.HandleFunc("GET /system/maint/logs", func(w http.ResponseWriter, r *http.Request) {
		q, err := parseLogQuery(r.URL.Query())
		if err != nil {
			reply(w, nil, err)
			return
		}
		view, err := m.Logs(r.Context(), q)
		reply(w, view, err)
	})
	mux.HandleFunc("GET /system/maint/logs.txt", func(w http.ResponseWriter, r *http.Request) {
		q, err := parseLogQuery(r.URL.Query())
		if err == nil {
			err = m.LogsText(r.Context(), w, q)
		}
		if err != nil && w.Header().Get("Content-Disposition") == "" {
			http.Error(w, err.Error(), http.StatusConflict)
		}
	})
	mux.HandleFunc("GET /system/maint/sources", func(w http.ResponseWriter, r *http.Request) {
		reply(w, m.Sources(r.Context()), nil)
	})
	mux.HandleFunc("POST /system/maint/test", func(w http.ResponseWriter, r *http.Request) {
		var q TestRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&q); err != nil {
			reply(w, nil, errors.New("bad request"))
			return
		}
		result, err := m.Test(r.Context(), q, user(r))
		reply(w, result, err)
	})
	mux.HandleFunc("GET /system/maint/backup", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Backup(r.Context(), w, panelUnit(r), user(r)); err != nil {
			log.Printf("backup: %v", err)
		}
	})
}
