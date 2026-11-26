package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pendingFile = "pending.json"
	watchEvery  = 2 * time.Second
	retryEvery  = 10 * time.Second
	// settle is how long VPP's API socket must exist before restoring, without -vpp-unit.
	settle       = 30 * time.Second
	readyTimeout = 90 * time.Second
	// verifyTimeout is how long a restarted VPP has to show the new settings, as its startup
	// CLI file may still be running when the API answers.
	verifyTimeout = 30 * time.Second
)

// Options configures the service.
type Options struct {
	StartConf  string // VPP's startup file: cpu section, dpdk devices
	CLIFile    string // the CLI file it runs: NAT44-EI lines
	ConfigFile string // RX modes, placement, governors
	APISocket  string
	VPPUnit    string
	StateDir   string
	Confirm    time.Duration
	MaxWorkers int // -1 for no limit beyond the CPUs
	// OtherPending is vpp-interfaces' pending change. It edits the same CLI file and puts the
	// whole file back on rollback, so neither starts a change while the other waits.
	OtherPending string
	// WireGuardStore is vpp-wireguard's configurations. It runs their commands' NAT44 lines in
	// the running plugin's form, so a switch only reads it, for commands with no equivalent.
	WireGuardStore string
	Sysfs          string
	// RouterEnv is the installer's router.env, whose NICS vpp-router-ctl binds before VPP starts;
	// NICsOrig is where the installer notes each card's first driver; PCIIDs is DPDK's PCI ID
	// table; UnitFile is VPP's unit file. Empty RouterEnv turns adding cards off.
	RouterEnv       string
	NICsOrig        string
	PCIIDs          string
	UnitFile        string
	CPUAffinityFile string // systemd's installer-managed default CPU affinity
	// DPDKPlugin is VPP's dpdk plugin, found from the startup file's plugin path when empty.
	DPDKPlugin string
}

// Pending is a change that restarted VPP and waits for confirmation.
type Pending struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	User        string    `json:"user"`
	Deadline    time.Time `json:"deadline"`
	// Files are the files changed, each backed up in the state directory under its base name.
	Files        []string `json:"files"`
	MissingFiles []string `json:"missing_files,omitempty"` // created by this change; removed on rollback
	// Device is the card the change added, given back to its driver on rollback.
	Device *AddedNIC `json:"device,omitempty"`
	// Retired is the card the change took out of VPP, given back to its driver; a rollback puts
	// the files back and vpp-router-ctl prep binds it again.
	Retired *AddedNIC `json:"retired,omitempty"`
}

// Result is how the last confirmable change ended.
type Result struct {
	Description string    `json:"description"`
	Outcome     string    `json:"outcome"`
	Detail      string    `json:"detail"`
	Time        time.Time `json:"time"`
}

// Service makes one change at a time.
type Service struct {
	opts       Options
	dial       func() (vppAPI, error)
	host       host
	restart    func(unit string) error
	stop       func(unit string) error
	unitActive func(unit string) bool
	unitFailed func(unit string) bool
	stamp      func() (fileStamp, error)
	reloadCPU  func() error
	now        func() time.Time
	sleep      func(time.Duration)

	mu         sync.Mutex
	cfg        *Config
	pending    *Pending
	last       *Result
	timer      *time.Timer
	nextID     int
	applied    fileStamp // the VPP run RX settings were put back on
	retryAt    time.Time
	applyError string
	warnings   []string
}

func systemctl(args ...string) error { return exec.Command("systemctl", args...).Run() }

func NewService(opts Options, dial func() (vppAPI, error)) (*Service, error) {
	if opts.Confirm <= 0 {
		opts.Confirm = time.Minute
	}
	if opts.Sysfs == "" {
		opts.Sysfs = "/sys"
	}
	cfg, err := loadConfig(opts.ConfigFile)
	if err != nil {
		return nil, err
	}
	s := &Service{
		opts: opts, dial: dial, cfg: cfg, now: time.Now, sleep: time.Sleep,
		host: host{sysfs: opts.Sysfs, proc: "/proc", addrs: hostAddrs, channels: hostChannels},
		restart: func(unit string) error {
			output, err := exec.Command("systemctl", "restart", "--no-block", unit).CombinedOutput()
			if err != nil {
				return fmt.Errorf("systemctl restart %s: %v: %s", unit, err, strings.TrimSpace(string(output)))
			}
			return nil
		},
		stop: func(unit string) error {
			output, err := exec.Command("systemctl", "stop", unit).CombinedOutput()
			if err != nil {
				return fmt.Errorf("systemctl stop %s: %v: %s", unit, err, strings.TrimSpace(string(output)))
			}
			return nil
		},
		unitActive: func(unit string) bool { return systemctl("is-active", "--quiet", unit) == nil },
		unitFailed: func(unit string) bool { return systemctl("is-failed", "--quiet", unit) == nil },
		stamp:      func() (fileStamp, error) { return stampOf(opts.APISocket) },
		reloadCPU: func() error {
			if err := systemctl("daemon-reload"); err != nil {
				return err
			}
			return systemctl("daemon-reexec")
		},
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	return s, nil
}

// Start finishes what a previous run left, and sets the governors.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for policy, governor := range s.cfg.Governors {
		if err := s.host.setGovernor(policy, governor); err != nil {
			log.Printf("governor: %v", err)
		} else {
			log.Printf("governor: %s %s", policy, governor)
		}
	}
	data, err := os.ReadFile(filepath.Join(s.opts.StateDir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending Pending
	if err := json.Unmarshal(data, &pending); err != nil {
		return fmt.Errorf("%s: %w", pendingFile, err)
	}
	s.pending = &pending
	if !s.now().Before(pending.Deadline) {
		s.rollbackLocked("管理服务重启时改动还没有确认")
		return nil
	}
	s.arm()
	return nil
}

func (s *Service) arm() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.pending.Deadline.Sub(s.now()), s.expire)
}

func (s *Service) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && !s.now().Before(s.pending.Deadline) {
		s.rollbackLocked("没有在期限内确认")
	}
}

func (s *Service) finish(description, outcome, detail string) {
	s.last = &Result{Description: description, Outcome: outcome, Detail: detail, Time: s.now()}
	log.Printf("audit: %s: %s %s", description, outcome, detail)
}

func (s *Service) backupPath(file string) string {
	return filepath.Join(s.opts.StateDir, filepath.Base(file)+".bak")
}

func (s *Service) savePending() error {
	data, err := json.Marshal(s.pending)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.opts.StateDir, pendingFile), data, 0o600)
}

func (s *Service) clearPending() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	for _, file := range s.pending.Files {
		os.Remove(s.backupPath(file))
	}
	s.pending = nil
	os.Remove(filepath.Join(s.opts.StateDir, pendingFile))
}

// otherPending says why a change cannot start now.
func (s *Service) otherPending() error {
	if s.pending != nil {
		return errors.New("还有改动等待确认")
	}
	if s.opts.OtherPending != "" {
		if _, err := os.Stat(s.opts.OtherPending); err == nil {
			return errors.New("接口页还有改动等待确认，确认或恢复后再改")
		}
	}
	return nil
}

// ready waits until the unit is active and a new VPP, one whose API socket is not the one
// stamped before, answers.
func (s *Service) ready(before fileStamp) error {
	deadline := s.now().Add(readyTimeout)
	for s.now().Before(deadline) {
		if stamp, err := s.stamp(); err != nil || stamp == before {
			s.sleep(500 * time.Millisecond)
			continue
		}
		if s.unitActive(s.opts.VPPUnit) {
			if v, err := s.dial(); err == nil {
				_, err = v.Threads()
				v.Close()
				if err == nil {
					return nil
				}
			}
		} else if s.unitFailed(s.opts.VPPUnit) {
			return errors.New(s.opts.VPPUnit + " 启动失败")
		}
		s.sleep(time.Second)
	}
	return fmt.Errorf("%s 在 %d 秒内没有恢复", s.opts.VPPUnit, int(readyTimeout.Seconds()))
}

func (s *Service) restartVPP() error {
	before, _ := s.stamp()
	if err := s.restart(s.opts.VPPUnit); err != nil {
		return err
	}
	return s.ready(before)
}

// verify waits for the restarted VPP to show what the change asked for.
func (s *Service) verify(check func(vppAPI) error) error {
	deadline := s.now().Add(verifyTimeout)
	for {
		v, err := s.dial()
		if err == nil {
			err = check(v)
			v.Close()
		}
		if err == nil || !s.now().Before(deadline) {
			return err
		}
		s.sleep(time.Second)
	}
}

func (s *Service) restoreFiles(files []string) error {
	var first error
	for _, file := range files {
		if slices.Contains(s.pending.MissingFiles, file) {
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
				first = err
			}
			continue
		}
		data, err := os.ReadFile(s.backupPath(file))
		if err == nil {
			err = writeFileAtomic(file, data, fileMode(file))
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Service) rollbackLocked(reason string) {
	description := s.pending.Description
	device := s.pending.Device
	if device != nil {
		// Stopped with the files that name the card, so vpp-router-ctl release undoes what its
		// prep did to it; then the card is free to go back to its driver.
		if err := s.stop(s.opts.VPPUnit); err != nil {
			s.finish(description, "rollback-failed", reason+"：停止 VPP 失败："+err.Error())
			return
		}
	}
	if err := s.restoreFiles(s.pending.Files); err != nil {
		s.finish(description, "rollback-failed", reason+"：恢复配置文件失败："+err.Error())
		return // the backups stay, for someone to look at
	}
	var problems []string
	cpuRestoreFailed := false
	if slices.Contains(s.pending.Files, s.opts.CPUAffinityFile) {
		if err := s.reloadCPU(); err != nil {
			cpuRestoreFailed = true
			problems = append(problems, "恢复 systemd CPU 亲和性："+err.Error())
		}
	}
	if device != nil {
		if err := s.host.giveBack(device); err != nil {
			problems = append(problems, "网卡没有交还给原驱动："+err.Error())
		}
	}
	if err := s.restartVPP(); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		s.finish(description, "rollback-failed", reason+"：文件已恢复，"+strings.Join(problems, "；"))
	} else {
		s.finish(description, "rolled-back", reason)
	}
	if cpuRestoreFailed {
		return
	} // keep the persisted transaction and backups for retry
	s.clearPending()
}

// restartChange writes the files, restarts VPP and leaves the change waiting for confirmation.
// files maps each path to its new content.
func (s *Service) restartChange(user, description string, files map[string]string, device, retired *AddedNIC, check func(vppAPI) error) (*State, error) {
	if s.opts.VPPUnit == "" {
		return nil, errors.New("这个改动要重启 VPP，但管理服务没有设置 --vpp-unit")
	}
	var paths []string
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	backups := map[string]string{}
	for _, path := range paths {
		if other, ok := backups[s.backupPath(path)]; ok {
			return nil, fmt.Errorf("%s 和 %s 同名，备份会互相覆盖，先把其中一个改名", other, path)
		}
		backups[s.backupPath(path)] = path
	}
	var missing []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && path == s.opts.CPUAffinityFile {
			missing = append(missing, path)
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(s.backupPath(path), data, 0o600); err != nil {
			return nil, err
		}
	}
	s.nextID++
	s.pending = &Pending{ID: strconv.FormatInt(s.now().Unix(), 10) + "-" + strconv.Itoa(s.nextID), Description: description, User: user, Files: paths, MissingFiles: missing, Device: device, Retired: retired}
	// Saved before anything changes, so a crash from here on still rolls back.
	s.pending.Deadline = s.now().Add(readyTimeout + verifyTimeout + s.opts.Confirm)
	if err := s.savePending(); err != nil {
		s.clearPending()
		return nil, err
	}
	if retired != nil {
		// Stopped with the files that still name the card, so vpp-router-ctl release undoes what
		// its prep did to it, and VPP lets go of it.
		if err := s.stop(s.opts.VPPUnit); err != nil {
			s.clearPending()
			return nil, fmt.Errorf("停止 VPP 失败：%w", err)
		}
	}
	for _, path := range paths {
		if err := writeFileAtomic(path, []byte(files[path]), fileMode(path)); err != nil {
			s.restoreFiles(paths)
			if retired != nil {
				s.restartVPP()
			}
			s.clearPending()
			return nil, err
		}
	}
	if retired != nil {
		if err := s.host.giveBack(retired); err != nil {
			s.rollbackLocked("网卡没有交还给原驱动：" + err.Error())
			return nil, fmt.Errorf("网卡没有交还给原驱动，已恢复旧配置：%w", err)
		}
	}
	if slices.Contains(paths, s.opts.CPUAffinityFile) {
		if err := s.reloadCPU(); err != nil {
			s.rollbackLocked("应用 systemd CPU 亲和性失败：" + err.Error())
			return nil, fmt.Errorf("应用 systemd CPU 亲和性失败：%w", err)
		}
	}
	log.Printf("audit: %s applied by %s, restarting VPP", description, user)
	err := s.restartVPP()
	if err == nil {
		err = s.verify(check)
	}
	if err != nil {
		s.rollbackLocked("VPP 没有按新配置运行：" + err.Error())
		return nil, fmt.Errorf("VPP 没有按新配置运行，已恢复旧配置：%w", err)
	}
	s.pending.Deadline = s.now().Add(s.opts.Confirm)
	if err := s.savePending(); err != nil {
		s.rollbackLocked("保存待确认状态失败：" + err.Error())
		return nil, err
	}
	s.arm()
	return s.stateLocked(), nil
}

func (s *Service) Confirm(user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil, errors.New("没有等待确认的改动")
	}
	description := s.pending.Description
	if r := s.pending.Retired; r != nil && r.Name != "" {
		// The interface is gone for good: its RX settings would only warn at each start.
		cfg := s.cfg.clone()
		delete(cfg.RxModes, r.Name)
		delete(cfg.RxPlacement, r.Name)
		if err := s.saveConfig(cfg); err != nil {
			log.Printf("forgetting the RX settings of %s: %v", r.Name, err)
		}
	}
	s.clearPending()
	s.finish(description, "confirmed", "由 "+user+" 确认")
	return s.stateLocked(), nil
}

func (s *Service) Rollback(user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil, errors.New("没有等待确认的改动")
	}
	s.rollbackLocked("由 " + user + " 撤销")
	return s.stateLocked(), nil
}

// Files.

func (s *Service) loadStartConf() (*startConf, error) {
	data, err := os.ReadFile(s.opts.StartConf)
	if err != nil {
		return nil, err
	}
	conf, err := parseStartConf(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s：%w", s.opts.StartConf, err)
	}
	return conf, nil
}

func (s *Service) loadCLI() (*cliFile, error) {
	data, err := os.ReadFile(s.opts.CLIFile)
	if err != nil {
		return nil, err
	}
	return parseCLI(string(data)), nil
}

// NAT44.

func checkTimeouts(t natTimeouts) error {
	for _, v := range []struct {
		name  string
		value uint32
	}{{"UDP", t.UDP}, {"TCP 已建立", t.TCPEstablished}, {"TCP 握手和关闭", t.TCPTransitory}, {"ICMP", t.ICMP}} {
		if v.value < 10 || v.value > 7*86400 {
			return fmt.Errorf("%s 超时要在 10 秒到 7 天（604800 秒）之间", v.name)
		}
	}
	return nil
}

// SetNATTimeouts changes the timeouts live and in the CLI file. Sessions already open keep
// the timeout they started with only until their next packet.
func (s *Service) SetNATTimeouts(t natTimeouts, user string) (*State, error) {
	if err := checkTimeouts(t); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	file, err := s.loadCLI()
	if err != nil {
		return nil, err
	}
	mode := file.natMode()
	if !file.setTimeouts(t) {
		return nil, errors.New(s.opts.CLIFile + " 里没有启用 NAT44（nat44 ei plugin enable 或 nat44 plugin enable）")
	}
	v, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer v.Close()
	running, err := v.NAT()
	if err != nil {
		return nil, err
	}
	if running == nil {
		return nil, errors.New("VPP 没有 NAT44 插件")
	}
	if running.Mode != mode {
		return nil, fmt.Errorf("%s 里是 %s 的命令，VPP 运行的却是 %s", s.opts.CLIFile, mode, running.Mode)
	}
	if err := v.SetNATTimeouts(t); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(s.opts.CLIFile, []byte(file.String()), fileMode(s.opts.CLIFile)); err != nil {
		v.SetNATTimeouts(running.Timeouts)
		return nil, err
	}
	log.Printf("audit: %s timeouts udp %d tcp-established %d tcp-transitory %d icmp %d by %s", mode, t.UDP, t.TCPEstablished, t.TCPTransitory, t.ICMP, user)
	return s.stateLocked(), nil
}

func checkSize(mode natMode, size natSize) error {
	if size.Sessions < 1024 || size.Sessions > 1<<24 {
		return errors.New("会话数要在 1024 到 16777216 之间")
	}
	if mode == natED {
		return nil // no users
	}
	if size.Users < 1 || size.Users > 1<<20 {
		return errors.New("用户数要在 1 到 1048576 之间")
	}
	if size.UserSessions < 1 || size.UserSessions > size.Sessions {
		return errors.New("每个用户的会话数要在 1 到会话数之间")
	}
	return nil
}

// SetNATSize changes the table sizes, which VPP takes only when the plugin is enabled.
func (s *Service) SetNATSize(size natSize, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	file, err := s.loadCLI()
	if err != nil {
		return nil, err
	}
	mode := file.natMode()
	if mode == natED {
		size.Users, size.UserSessions = 0, 0
	}
	if err := checkSize(mode, size); err != nil {
		return nil, err
	}
	if current, ok := file.natSize(); ok && current == size {
		return nil, errors.New("没有改动")
	}
	if !file.setNATSize(size) {
		return nil, errors.New(s.opts.CLIFile + " 里没有启用 NAT44（nat44 ei plugin enable 或 nat44 plugin enable）")
	}
	description := fmt.Sprintf("%s 会话表：每线程 %d 个会话、%d 个用户，每个用户 %d 个会话", mode, size.Sessions, size.Users, size.UserSessions)
	if mode == natED {
		description = fmt.Sprintf("%s 会话表：每线程 %d 个会话", mode, size.Sessions)
	}
	return s.restartChange(user, description, map[string]string{s.opts.CLIFile: file.String()}, nil, nil, func(v vppAPI) error {
		running, err := v.NAT()
		if err != nil {
			return err
		}
		if running == nil || running.Mode != mode || running.Size.Sessions != size.Sessions || mode == natEI && (running.Size.Users != size.Users || running.Size.UserSessions != size.UserSessions) {
			return fmt.Errorf("%s 的会话表大小不是新设置的值（插件可能启用失败，比如内存不够）", mode)
		}
		return nil
	})
}

// natModeFiles are the CLI file and the files it runs with exec, at any depth, with their NAT44
// commands rewritten for mode: the new text of each file that changes, keyed by path. The CLI
// file is always included. It refuses commands that have no equivalent, naming their file, and
// the WireGuard configurations' commands that have none (see wireGuardNATProblems).
func (s *Service) natModeFiles(file *cliFile, mode natMode) (map[string]string, error) {
	type found struct {
		path string
		file *cliFile
	}
	var all []found
	seen := map[string]bool{s.opts.CLIFile: true}
	var walk func(path string, f *cliFile) error
	walk = func(path string, f *cliFile) error {
		all = append(all, found{path, f})
		for _, next := range f.execFiles() {
			if seen[next] {
				continue
			}
			seen[next] = true
			data, err := os.ReadFile(next)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // VPP reports it at start, as it did before
				}
				return fmt.Errorf("%s 执行的 %s 读不出来：%w", path, next, err)
			}
			if err := walk(next, parseCLI(string(data))); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(s.opts.CLIFile, file); err != nil {
		return nil, err
	}
	configs, err := s.wireGuardConfigs()
	if err != nil {
		return nil, err
	}
	m := newMultiExit()
	for _, f := range all {
		m.scan(f.file.lines)
	}
	for _, c := range configs {
		for _, address := range c.Addresses {
			m.addOwn(c.iface(), address)
		}
		m.scan(c.AfterUp)
	}
	files := map[string]string{}
	var problems []string
	for _, f := range all {
		out, bad := f.file.withNATMode(mode, m)
		if len(bad) > 0 {
			problems = append(problems, f.path+" 里的 "+strings.Join(bad, "；"))
		}
		if f.path == s.opts.CLIFile || out.String() != f.file.String() {
			files[f.path] = out.String()
		}
	}
	problems = append(problems, wireGuardNATProblems(configs, mode, m)...)
	if len(problems) > 0 {
		return nil, fmt.Errorf("这些 NAT 命令在 %s 里没有对应的写法，先改掉：%s", mode, strings.Join(problems, "；"))
	}
	return files, nil
}

// wgConfig is what a switch reads of a vpp-wireguard configuration.
type wgConfig struct {
	Name       string   `json:"name"`
	Instance   int      `json:"instance"`
	Addresses  []string `json:"addresses"`
	AfterUp    []string `json:"after_up"`
	BeforeDown []string `json:"before_down"`
}

func (c wgConfig) iface() string { return "wg" + strconv.Itoa(c.Instance) }

func (s *Service) wireGuardConfigs() ([]wgConfig, error) {
	if s.opts.WireGuardStore == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.opts.WireGuardStore)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读不出 WireGuard 配置 %s：%w", s.opts.WireGuardStore, err)
	}
	var store struct {
		Configs []wgConfig `json:"configs"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("WireGuard 配置 %s 无法解析", s.opts.WireGuardStore)
	}
	return store.Configs, nil
}

// wireGuardNATProblems names the WireGuard configurations' commands that are NAT44 commands
// with no equivalent in mode. vpp-wireguard runs them in the running plugin's form: under ED it
// skips the EI-only multi-exit commands and drops tenant-vrf from the pool address of a
// configuration that has a context, so they are checked as the files are. The commands are not
// quoted: the file holds private keys, and nothing of it reaches a reply.
func wireGuardNATProblems(configs []wgConfig, mode natMode, m *multiExit) []string {
	var problems []string
	for _, c := range configs {
		hasContext := slices.ContainsFunc(c.AfterUp, func(command string) bool { return hasWords(cliFields(command), "nat44", "ei", "context") })
		for _, list := range []struct {
			what     string
			commands []string
		}{{"接口附加命令", c.AfterUp}, {"停止前命令", c.BeforeDown}} {
			for i, command := range list.commands {
				f := cliFields(command)
				if !isNATCommand(f) || lineMode(f) == mode {
					continue
				}
				where := fmt.Sprintf("VPN「%s」（%s）的%s第 %d 条", c.Name, c.iface(), list.what, i+1)
				if mode == natED {
					problem := m.edProblem(f)
					if problem == "" && hasContext && tenantVRF(f) != "" {
						if _, ok := m.exitOf(tenantVRF(f)); !ok {
							problem = "tenant-vrf " + tenantVRF(f) + " 不是这个 VPN 的 nat44 ei context 的路由表"
						}
					}
					if problem != "" {
						problems = append(problems, where+"（"+problem+"）")
						continue
					}
					if isEIOnly(f) {
						continue
					}
					if hasContext {
						f = withoutTenantVRF(f)
					}
				}
				if _, ok := translateNAT(f, mode); !ok {
					problems = append(problems, where)
				}
			}
		}
	}
	return problems
}

// SetNATMode makes VPP run the other NAT44 plugin: the startup file loads it instead and every
// NAT44 command in the CLI file is rewritten for it. VPP restarts, losing its NAT sessions, and
// the change waits for confirmation. Port forwards and the other services' mappings are put
// back by their services, which follow the plugin VPP runs.
func (s *Service) SetNATMode(mode natMode, user string) (*State, error) {
	if mode != natEI && mode != natED {
		return nil, errors.New("NAT 模式只能是 ei 或 ed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	conf, err := s.loadStartConf()
	if err != nil {
		return nil, err
	}
	current, err := conf.natMode()
	if err != nil {
		return nil, err
	}
	if current == mode {
		return nil, errors.New("NAT 已经是 " + mode.String())
	}
	file, err := s.loadCLI()
	if err != nil {
		return nil, err
	}
	files, err := s.natModeFiles(file, mode)
	if err != nil {
		return nil, err
	}
	newConf, err := conf.withNATMode(mode)
	if err != nil {
		return nil, err
	}
	description := fmt.Sprintf("NAT 模式由 %s 改为 %s", current, mode)
	files[s.opts.StartConf] = newConf
	return s.restartChange(user, description, files, nil, nil, func(v vppAPI) error {
		running, err := v.NAT()
		if err != nil {
			return err
		}
		if running == nil || running.Mode != mode {
			return fmt.Errorf("VPP 运行的不是 %s（插件没有加载，或 %s 里的 NAT 命令执行失败）", mode, s.opts.CLIFile)
		}
		return nil
	})
}

// Threads.

type ThreadsRequest struct {
	MainCore int            `json:"main_core"`
	Workers  []int          `json:"workers"`
	Policy   string         `json:"scheduler_policy"`
	Priority *int           `json:"scheduler_priority"`
	RxQueues map[string]int `json:"rx_queues"`
}

var schedulerPolicies = []string{"other", "batch", "idle", "fifo", "rr"}

func (s *Service) checkThreads(q *ThreadsRequest, devs []DeviceView) error {
	online, err := s.host.online()
	if err != nil {
		return err
	}
	if !slices.Contains(online, q.MainCore) {
		return fmt.Errorf("没有 CPU %d", q.MainCore)
	}
	seen := map[int]bool{}
	for _, w := range q.Workers {
		if !slices.Contains(online, w) {
			return fmt.Errorf("没有 CPU %d", w)
		}
		if w == q.MainCore {
			return errors.New("worker 不能和主线程在同一个 CPU 上")
		}
		if seen[w] {
			return fmt.Errorf("CPU %d 重复", w)
		}
		seen[w] = true
	}
	if s.opts.MaxWorkers >= 0 && len(q.Workers) > s.opts.MaxWorkers {
		if s.opts.MaxWorkers == 0 {
			return errors.New("这个平台只能单线程运行，不能开 worker")
		}
		return fmt.Errorf("这个平台最多 %d 个 worker", s.opts.MaxWorkers)
	}
	if q.Policy != "" && !slices.Contains(schedulerPolicies, q.Policy) {
		return fmt.Errorf("调度策略 %q 不认识", q.Policy)
	}
	if q.Priority != nil {
		if q.Policy != "fifo" && q.Policy != "rr" {
			return errors.New("只有 fifo 和 rr 策略有优先级")
		}
		if *q.Priority < 1 || *q.Priority > 99 {
			return errors.New("优先级要在 1 到 99 之间")
		}
	}
	for address, n := range q.RxQueues {
		i := slices.IndexFunc(devs, func(d DeviceView) bool { return d.Address == address })
		if i < 0 || !devs[i].Editable {
			return fmt.Errorf("不能修改 %s 的收包队列数", address)
		}
		limit := devs[i].MaxQueues
		if limit == 0 {
			limit = 16
		}
		if n < 1 || n > limit {
			return fmt.Errorf("%s 的收包队列数要在 1 到 %d 之间", devs[i].label(), limit)
		}
	}
	return nil
}

// SetThreads changes VPP's thread layout and the DPDK devices' queue counts.
func (s *Service) SetThreads(q ThreadsRequest, user string) (*State, error) {
	slices.Sort(q.Workers)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	conf, err := s.loadStartConf()
	if err != nil {
		return nil, err
	}
	cpu, err := conf.cpu()
	if err != nil {
		return nil, err
	}
	devs := s.devices(conf, s.hardware())
	if err := s.checkThreads(&q, devs); err != nil {
		return nil, err
	}
	for address, n := range q.RxQueues {
		for _, d := range devs {
			if d.Address == address && d.FileQueues == n {
				delete(q.RxQueues, address)
			}
		}
	}
	main := q.MainCore
	next := &cpuConf{MainCore: &main, Workers: q.Workers, Policy: q.Policy, Priority: q.Priority, Other: cpu.Other}
	if cpuText(next) == cpuText(cpu) && len(q.RxQueues) == 0 {
		return nil, errors.New("没有改动")
	}
	text, err := conf.withThreads(next, q.RxQueues)
	if err != nil {
		return nil, err
	}
	description := fmt.Sprintf("VPP 线程：主线程 CPU %d，", q.MainCore)
	if len(q.Workers) > 0 {
		description += fmt.Sprintf("%d 个 worker（CPU %s）", len(q.Workers), formatCoreList(q.Workers))
	} else {
		description += "没有 worker"
	}
	if q.Policy != "" {
		description += "，调度 " + q.Policy
	}
	for address, n := range q.RxQueues {
		description += fmt.Sprintf("，%s %d 个收包队列", address, n)
	}
	files := map[string]string{s.opts.StartConf: text}
	if err := s.workerCPUFiles(q.Workers, files); err != nil {
		return nil, err
	}
	return s.restartChange(user, description, files, nil, nil, func(v vppAPI) error {
		threads, err := v.Threads()
		if err != nil {
			return err
		}
		var workers []int
		mainCPU := -1
		for _, t := range threads {
			if t.Index == 0 {
				mainCPU = t.CPU
			} else if t.Type == "workers" {
				workers = append(workers, t.CPU)
			}
		}
		slices.Sort(workers)
		if mainCPU != q.MainCore || !slices.Equal(workers, q.Workers) {
			return fmt.Errorf("VPP 的线程不是新设置的布局：主线程在 CPU %d，worker 在 %v", mainCPU, workers)
		}
		return nil
	})
}

// RX modes and placement.

func (s *Service) saveConfig(cfg *Config) error {
	if err := cfg.save(s.opts.ConfigFile); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

func queuesOf(queues []rxQueue, name string) []rxQueue {
	var list []rxQueue
	for _, q := range queues {
		if q.Interface == name {
			list = append(list, q)
		}
	}
	return list
}

// SetRxMode sets how every queue of an interface receives, now and after each VPP start.
// "default" forgets the setting and leaves VPP as it is.
func (s *Service) SetRxMode(name, mode, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return nil, errors.New("还有改动等待确认")
	}
	cfg := s.cfg.clone()
	if mode == "default" {
		delete(cfg.RxModes, name)
		if err := s.saveConfig(cfg); err != nil {
			return nil, err
		}
		log.Printf("audit: rx-mode %s forgotten by %s", name, user)
		return s.stateLocked(), nil
	}
	if _, ok := modeValue(mode); !ok {
		return nil, fmt.Errorf("收包方式 %q 不认识", mode)
	}
	v, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer v.Close()
	all, err := v.RxQueues()
	if err != nil {
		return nil, err
	}
	before := queuesOf(all, name)
	if len(before) == 0 {
		return nil, fmt.Errorf("%s 没有收包队列", name)
	}
	if err := setMode(v, before, mode); err != nil {
		return nil, err
	}
	if cfg.RxModes == nil {
		cfg.RxModes = map[string]string{}
	}
	cfg.RxModes[name] = mode
	if err := s.saveConfig(cfg); err != nil {
		v.SetRxMode(before[0].Index, before[0].Mode)
		return nil, err
	}
	log.Printf("audit: rx-mode %s %s by %s", name, mode, user)
	return s.stateLocked(), nil
}

// setMode sets the mode and checks VPP took it: one that cannot is refused by some drivers,
// and shown as still polling by others.
func setMode(v vppAPI, before []rxQueue, mode string) error {
	index := before[0].Index
	if err := v.SetRxMode(index, mode); err != nil {
		return fmt.Errorf("%s 不支持 %s：%w", before[0].Interface, modeLabel(mode), err)
	}
	all, err := v.RxQueues()
	if err != nil {
		return err
	}
	for _, q := range queuesOf(all, before[0].Interface) {
		if q.Mode != mode {
			v.SetRxMode(index, before[0].Mode)
			return fmt.Errorf("%s 不支持%s收包，保持%s", q.Interface, modeLabel(mode), modeLabel(before[0].Mode))
		}
	}
	return nil
}

func modeLabel(mode string) string {
	switch mode {
	case "polling":
		return "轮询"
	case "interrupt":
		return "中断"
	case "adaptive":
		return "自适应"
	}
	return mode
}

func threadLabel(thread uint32) string {
	if thread == 0 {
		return "主线程"
	}
	return fmt.Sprintf("worker %d", thread-1)
}

// SetRxPlacement moves one queue to a thread, now and after each VPP start. A negative thread
// forgets the setting.
func (s *Service) SetRxPlacement(name string, queue uint32, thread int, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return nil, errors.New("还有改动等待确认")
	}
	cfg := s.cfg.clone()
	if thread < 0 {
		delete(cfg.RxPlacement[name], queue)
		if len(cfg.RxPlacement[name]) == 0 {
			delete(cfg.RxPlacement, name)
		}
		if err := s.saveConfig(cfg); err != nil {
			return nil, err
		}
		log.Printf("audit: rx-placement %s queue %d forgotten by %s", name, queue, user)
		return s.stateLocked(), nil
	}
	v, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer v.Close()
	threads, err := v.Threads()
	if err != nil {
		return nil, err
	}
	if !hasThread(threads, uint32(thread)) {
		return nil, fmt.Errorf("没有%s", threadLabel(uint32(thread)))
	}
	all, err := v.RxQueues()
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(all, func(q rxQueue) bool { return q.Interface == name && q.Queue == queue })
	if i < 0 {
		return nil, fmt.Errorf("%s 没有队列 %d", name, queue)
	}
	old := all[i]
	if err := v.SetRxPlacement(old.Index, queue, uint32(thread)); err != nil {
		return nil, err
	}
	if cfg.RxPlacement == nil {
		cfg.RxPlacement = map[string]map[uint32]uint32{}
	}
	if cfg.RxPlacement[name] == nil {
		cfg.RxPlacement[name] = map[uint32]uint32{}
	}
	cfg.RxPlacement[name][queue] = uint32(thread)
	if err := s.saveConfig(cfg); err != nil {
		v.SetRxPlacement(old.Index, queue, old.Thread)
		return nil, err
	}
	log.Printf("audit: rx-placement %s queue %d on %s by %s", name, queue, threadLabel(uint32(thread)), user)
	return s.stateLocked(), nil
}

func hasThread(threads []thread, index uint32) bool {
	return slices.ContainsFunc(threads, func(t thread) bool { return t.Index == index && (index == 0 || t.Type == "workers") })
}

// reapply puts the RX settings back on a VPP that has just started. What cannot be done, such
// as a placement on a worker there no longer is, is skipped and reported.
func (s *Service) reapply(v vppAPI) (warnings []string, err error) {
	if len(s.cfg.RxModes) == 0 && len(s.cfg.RxPlacement) == 0 {
		return nil, nil
	}
	all, err := v.RxQueues()
	if err != nil {
		return nil, err
	}
	threads, err := v.Threads()
	if err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(s.cfg.RxModes)) {
		mode := s.cfg.RxModes[name]
		queues := queuesOf(all, name)
		if len(queues) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s 不存在，收包方式没有设置", name))
			continue
		}
		if !slices.ContainsFunc(queues, func(q rxQueue) bool { return q.Mode != mode }) {
			continue
		}
		if err := setMode(v, queues, mode); err != nil {
			warnings = append(warnings, err.Error())
		}
	}
	for name, placement := range s.cfg.RxPlacement {
		for queue, t := range placement {
			i := slices.IndexFunc(all, func(q rxQueue) bool { return q.Interface == name && q.Queue == queue })
			switch {
			case i < 0:
				warnings = append(warnings, fmt.Sprintf("%s 没有队列 %d，收包线程没有设置", name, queue))
			case !hasThread(threads, t):
				warnings = append(warnings, fmt.Sprintf("没有%s，%s 队列 %d 由 VPP 分配", threadLabel(t), name, queue))
			case all[i].Thread != t:
				if err := v.SetRxPlacement(all[i].Index, queue, t); err != nil {
					warnings = append(warnings, fmt.Sprintf("%s 队列 %d：%v", name, queue, err))
				}
			}
		}
	}
	slices.Sort(warnings)
	return warnings, nil
}

// tick puts the RX settings back after VPP starts.
func (s *Service) tick(now time.Time) {
	stamp, err := s.stamp()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stamp == s.applied || now.Before(s.retryAt) {
		return
	}
	if s.opts.VPPUnit != "" {
		if !s.unitActive(s.opts.VPPUnit) {
			return
		}
	} else if now.Sub(time.Unix(0, stamp.Ctime)) < settle {
		return
	}
	v, err := s.dial()
	if err == nil {
		var warnings []string
		warnings, err = s.reapply(v)
		v.Close()
		s.warnings = warnings
		for _, w := range warnings {
			log.Printf("apply: %s", w)
		}
	}
	if err != nil {
		s.applyError = err.Error()
		s.retryAt = now.Add(retryEvery)
		log.Printf("apply: %v", err)
		return
	}
	s.applied = stamp
	s.applyError = ""
}

func (s *Service) watch() {
	for range time.Tick(watchEvery) {
		s.tick(s.now())
	}
}

// Governors.

// SetGovernor sets a cpufreq policy's governor, now and at each boot. An empty governor
// forgets the setting and leaves the policy as it is.
func (s *Service) SetGovernor(policy, governor, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.cfg.clone()
	if governor == "" {
		delete(cfg.Governors, policy)
	} else {
		if err := s.host.setGovernor(policy, governor); err != nil {
			return nil, err
		}
		if cfg.Governors == nil {
			cfg.Governors = map[string]string{}
		}
		cfg.Governors[policy] = governor
	}
	if err := s.saveConfig(cfg); err != nil {
		return nil, err
	}
	log.Printf("audit: governor %s %q by %s", policy, governor, user)
	return s.stateLocked(), nil
}

// The panel's view.

type DeviceView struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	// FileQueues is num-rx-queues in the file, 0 when not given; DefaultQueues is dev default's.
	FileQueues    int  `json:"file_queues"`
	DefaultQueues int  `json:"default_queues"`
	Queues        int  `json:"queues"`     // as VPP runs it
	MaxQueues     int  `json:"max_queues"` // 0 when unknown
	Editable      bool `json:"editable"`
}

func (d DeviceView) label() string {
	if d.Name != "" {
		return d.Name
	}
	return d.Address
}

type ThreadsView struct {
	Live       []thread     `json:"live"`
	File       *cpuConf     `json:"file"`
	MaxWorkers int          `json:"max_workers"`
	Devices    []DeviceView `json:"devices"`
	Policies   []string     `json:"policies"`
	Error      string       `json:"error"`
}

type QueueView struct {
	Queue  uint32 `json:"queue"`
	Thread uint32 `json:"thread"`
	Mode   string `json:"mode"`
	// Setting is the thread this program puts it on, null when VPP chooses.
	Setting *uint32 `json:"setting"`
}

type RxView struct {
	Name    string      `json:"name"`
	Queues  []QueueView `json:"queues"`
	Setting string      `json:"setting"` // the mode this program sets, empty when none
}

type NATView struct {
	Enabled bool `json:"enabled"` // the CLI file enables it
	// Mode is the plugin the startup file loads; FileMode the one the CLI file's enable line is for.
	Mode     natMode `json:"mode"`
	FileMode natMode `json:"file_mode"`
	// SwitchProblem is why the mode cannot be switched to the other plugin, empty when it can.
	SwitchProblem string      `json:"switch_problem"`
	Running       *natRunning `json:"running"`
	FileSize      natSize     `json:"file_size"`
	FileTimeouts  natTimeouts `json:"file_timeouts"`
	Defaults      natTimeouts `json:"defaults"`
}

type State struct {
	StartConf        string            `json:"start_conf"`
	CLIFile          string            `json:"cli_file"`
	CanRestart       bool              `json:"can_restart"`
	Error            string            `json:"error"`
	ApplyError       string            `json:"apply_error"`
	Warnings         []string          `json:"warnings"`
	OtherPending     bool              `json:"other_pending"`
	CPUs             []cpuInfo         `json:"cpus"`
	Governors        []policyInfo      `json:"governors"`
	GovernorSettings map[string]string `json:"governor_settings"`
	Threads          ThreadsView       `json:"threads"`
	Interfaces       []RxView          `json:"interfaces"`
	NAT              NATView           `json:"nat"`
	NICs             NICsView          `json:"nics"`
	Pending          *Pending          `json:"pending"`
	SecondsRemaining float64           `json:"seconds_remaining"`
	Last             *Result           `json:"last"`
}

func (s *Service) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateLocked()
}

// hardware is VPP's hardware listing, nil when it cannot be read.
func (s *Service) hardware() []hardware {
	v, err := s.dial()
	if err != nil {
		return nil
	}
	defer v.Close()
	text, err := v.CLI("show hardware-interfaces")
	if err != nil {
		return nil
	}
	return parseHardware(text)
}

// devices are the dpdk section's devices, with what VPP's hardware listing says about them.
func (s *Service) devices(conf *startConf, hw []hardware) []DeviceView {
	list := []DeviceView{}
	defaults := 0
	for _, d := range conf.dpdkDevs() {
		if d.Address == "default" {
			defaults = d.Queues
		}
	}
	for _, d := range conf.dpdkDevs() {
		if d.Address == "default" {
			continue
		}
		_, pci := pciAddress(d.Address)
		view := DeviceView{Address: d.Address, Name: d.Name, FileQueues: d.Queues, DefaultQueues: defaults, Editable: pci}
		for _, h := range hw {
			if (pci && sameAddress(h.PCI, d.Address)) || (d.Name != "" && h.Name == d.Name) {
				view.Queues, view.MaxQueues = h.Queues, h.MaxQueues
				if view.Name == "" {
					view.Name = h.Name
				}
			}
		}
		list = append(list, view)
	}
	return list
}

func (s *Service) stateLocked() *State {
	state := &State{
		StartConf: s.opts.StartConf, CLIFile: s.opts.CLIFile, CanRestart: s.opts.VPPUnit != "",
		ApplyError: s.applyError, Warnings: s.warnings, Pending: s.pending, Last: s.last,
		GovernorSettings: s.cfg.Governors, Interfaces: []RxView{},
		Threads: ThreadsView{MaxWorkers: s.opts.MaxWorkers, Policies: schedulerPolicies, Devices: []DeviceView{}},
		NAT:     NATView{Defaults: defaultTimeouts},
	}
	if s.pending != nil {
		state.SecondsRemaining = max(0, s.pending.Deadline.Sub(s.now()).Seconds())
	}
	if s.opts.OtherPending != "" {
		_, err := os.Stat(s.opts.OtherPending)
		state.OtherPending = err == nil
	}
	var errs []string
	state.Governors = s.host.policies()
	cpus, err := s.host.cpus(state.Governors)
	if err != nil {
		errs = append(errs, err.Error())
	}
	state.CPUs = cpus

	var hw []hardware
	var queues []rxQueue
	v, err := s.dial()
	if err != nil {
		errs = append(errs, "读取 VPP 失败："+err.Error())
	} else {
		state.Threads.Live, err = v.Threads()
		if err == nil {
			queues, err = v.RxQueues()
		}
		if err == nil {
			state.NAT.Running, err = v.NAT()
		}
		if err == nil {
			var text string
			if text, err = v.CLI("show hardware-interfaces"); err == nil {
				hw = parseHardware(text)
			}
		}
		v.Close()
		if err != nil {
			errs = append(errs, "读取 VPP 失败："+err.Error())
		}
	}

	if conf, err := s.loadStartConf(); err != nil {
		state.Threads.Error = err.Error()
	} else if cpu, err := conf.cpu(); err != nil {
		state.Threads.Error = err.Error()
	} else {
		state.Threads.File = cpu
		state.Threads.Devices = s.devices(conf, hw)
	}
	state.NICs = s.nicsView(hw)

	if file, err := s.loadCLI(); err != nil {
		errs = append(errs, err.Error())
	} else {
		state.NAT.FileSize, state.NAT.Enabled = file.natSize()
		state.NAT.FileTimeouts = file.timeouts()
		state.NAT.FileMode = file.natMode()
		if conf, err := s.loadStartConf(); err != nil {
			state.NAT.SwitchProblem = err.Error()
		} else if mode, err := conf.natMode(); err != nil {
			state.NAT.SwitchProblem = err.Error()
		} else {
			state.NAT.Mode = mode
			to := natED
			if mode == natED {
				to = natEI
			}
			if _, err := s.natModeFiles(file, to); err != nil {
				state.NAT.SwitchProblem = err.Error()
			} else if _, err := conf.withNATMode(to); err != nil {
				state.NAT.SwitchProblem = err.Error()
			}
		}
	}

	for _, q := range queues {
		i := slices.IndexFunc(state.Interfaces, func(r RxView) bool { return r.Name == q.Interface })
		if i < 0 {
			state.Interfaces = append(state.Interfaces, RxView{Name: q.Interface, Setting: s.cfg.RxModes[q.Interface]})
			i = len(state.Interfaces) - 1
		}
		view := QueueView{Queue: q.Queue, Thread: q.Thread, Mode: q.Mode}
		if t, ok := s.cfg.RxPlacement[q.Interface][q.Queue]; ok {
			view.Setting = &t
		}
		state.Interfaces[i].Queues = append(state.Interfaces[i].Queues, view)
	}
	state.Error = strings.Join(errs, "；")
	return state
}
