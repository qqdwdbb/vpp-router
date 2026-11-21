package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options configures the service.
type Options struct {
	SingBoxDir string // entry.json and upstream.json, loaded by sing-box with -C
	ConfigDir  string // the wizard's profile
	StateDir   string // the subscription and what it last returned
	Unit       string
	Binary     string
	TestURL    string
}

// system is what the service does to the machine.
type system interface {
	check(dir string) error                                                // sing-box check -C dir
	version() string                                                       // sing-box version
	unit(action string) error                                              // systemctl start|stop|restart
	active() bool                                                          // systemctl is-active
	probe(upstream map[string]any, url string) (int, time.Duration, error) // a request through a throwaway sing-box
	fetch(url string) (string, error)                                      // download a subscription
}

// Service applies changes one at a time.
type Service struct {
	opts  Options
	sys   system
	sleep func(time.Duration)
	mu    sync.Mutex
}

const (
	profileFile      = "profile.json"
	subscriptionFile = "subscription.json"
	upstreamFile     = "upstream.json"
	entryFile        = "entry.json"
)

// savedProfile is the wizard's profile with a digest of the upstream.json it produced, so a
// file someone changed by hand is told apart.
type savedProfile struct {
	Profile Profile `json:"profile"`
	Digest  string  `json:"digest"`
}

type subscription struct {
	URL     string    `json:"url"`
	Nodes   []Profile `json:"nodes"`
	Fetched time.Time `json:"fetched"`
	Using   string    `json:"using"` // the node in use, by name
}

func NewService(opts Options, sys system) (*Service, error) {
	for _, dir := range []string{opts.ConfigDir, opts.StateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Service{opts: opts, sys: sys, sleep: time.Sleep}, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

// Inbound is an entry the LAN reaches.
type Inbound struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Listen string `json:"listen"`
	Port   int    `json:"port"`
}

// State is what the panel shows. Secrets never leave the service.
type State struct {
	Installed bool      `json:"installed"`
	Running   bool      `json:"running"`
	Version   string    `json:"version"`
	Inbounds  []Inbound `json:"inbounds"`
	// Upstream is "none" (the placeholder), "wizard" (the profile below) or "custom".
	Upstream     string        `json:"upstream"`
	Profile      *Profile      `json:"profile"`
	SecretsSet   []string      `json:"secrets_set"`
	Custom       []string      `json:"custom"` // the outbounds and endpoints of a custom upstream
	Subscription *Subscription `json:"subscription"`
	Options      FormOptions   `json:"options"`
}

// Subscription is the subscription as the panel shows it: its nodes without secrets.
type Subscription struct {
	URL     string    `json:"url"`
	Fetched time.Time `json:"fetched"`
	Using   string    `json:"using"`
	Nodes   []Profile `json:"nodes"`
}

// FormOptions are the choices the wizard's lists offer.
type FormOptions struct {
	Protocols    map[string]string `json:"protocols"`
	TLS          map[string]string `json:"tls"`
	Transport    map[string]bool   `json:"transport"`
	Methods      []string          `json:"methods"`
	Fingerprints []string          `json:"fingerprints"`
	TestURL      string            `json:"test_url"`
}

func maskAll(nodes []Profile) []Profile {
	out := make([]Profile, len(nodes))
	for i, node := range nodes {
		out[i], _ = node.Masked()
	}
	return out
}

func (s *Service) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := &State{Inbounds: []Inbound{}, Custom: []string{}, SecretsSet: []string{},
		Options: FormOptions{Protocols: protocols, TLS: tlsUse, Transport: withTransport, Methods: shadowsocksMethods,
			Fingerprints: fingerprints, TestURL: s.opts.TestURL}}
	var entry struct {
		Inbounds []struct {
			Tag, Type, Listen string
			ListenPort        int `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := readJSON(filepath.Join(s.opts.SingBoxDir, entryFile), &entry); err == nil {
		state.Installed = true
		for _, in := range entry.Inbounds {
			state.Inbounds = append(state.Inbounds, Inbound{Tag: in.Tag, Type: in.Type, Listen: in.Listen, Port: in.ListenPort})
		}
	}
	if !state.Installed {
		return state
	}
	state.Running = s.sys.active()
	state.Version = s.sys.version()
	state.Upstream, state.Profile, state.Custom = s.upstreamLocked()
	if state.Profile != nil {
		masked, set := state.Profile.Masked()
		state.Profile, state.SecretsSet = &masked, set
	}
	var sub subscription
	if readJSON(filepath.Join(s.opts.StateDir, subscriptionFile), &sub) == nil {
		state.Subscription = &Subscription{URL: sub.URL, Fetched: sub.Fetched, Using: sub.Using, Nodes: maskAll(sub.Nodes)}
	}
	return state
}

// upstreamLocked tells what upstream.json holds: the placeholder, the wizard's profile, or
// something written by hand, listed by its outbounds and endpoints.
func (s *Service) upstreamLocked() (string, *Profile, []string) {
	data, err := os.ReadFile(filepath.Join(s.opts.SingBoxDir, upstreamFile))
	if err != nil {
		return "none", nil, []string{}
	}
	var saved savedProfile
	if readJSON(filepath.Join(s.opts.ConfigDir, profileFile), &saved) == nil && saved.Digest == digest(data) {
		return "wizard", &saved.Profile, []string{}
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return "custom", nil, []string{"upstream.json 不是合法的 JSON"}
	}
	// The installer's placeholder: a direct outbound behind a reject rule.
	if route, ok := doc["route"].(map[string]any); ok && len(asList(route["rules"])) > 0 && strings.Contains(string(data), `"reject"`) {
		return "none", nil, []string{}
	}
	var custom []string
	for _, item := range append(asList(doc["outbounds"]), asList(doc["endpoints"])...) {
		object, _ := item.(map[string]any)
		kind, _ := object["type"].(string)
		tag, _ := object["tag"].(string)
		server, _ := object["server"].(string)
		text := tag + "：" + kind
		if server != "" {
			text += " " + server
		}
		custom = append(custom, text)
	}
	return "custom", nil, custom
}

// Apply turns a profile into upstream.json and restarts sing-box. The configuration is checked
// first, and if sing-box does not come back, the previous upstream is put back.
func (s *Service) Apply(p Profile, user string) (*State, error) {
	s.mu.Lock()
	var saved savedProfile
	if readJSON(filepath.Join(s.opts.ConfigDir, profileFile), &saved) == nil {
		p.KeepSecrets(&saved.Profile)
	}
	p.Ignored = nil
	upstream, err := p.Upstream()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	err = s.writeUpstreamLocked(upstream, &p, user)
	if err == nil {
		// A subscription node sets it again once applied.
		s.setUsingLocked("")
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.State(), nil
}

// proxiedInbounds are the entries the placeholder turns away, as the installer writes it.
var proxiedInbounds = []string{tproxyInbound, "lan-socks"}

// tproxyInbound is the one TPROXY listener: it takes real addresses and, for the rules whose DNS
// is its Fake-IP DNS, the pool's addresses, which sing-box turns back into names.
const tproxyInbound = "tproxy"

// placeholder is the installer's upstream for none: a direct outbound behind a reject rule, so
// nothing leaves without a proxy.
func placeholder() map[string]any {
	return map[string]any{
		"outbounds": []any{map[string]any{"type": "direct", "tag": "proxy"}},
		"route":     map[string]any{"rules": []any{map[string]any{"inbound": proxiedInbounds, "action": "reject"}}},
	}
}

// Clear removes the upstream: upstream.json goes back to the placeholder, the old one kept as
// upstream.json.bak, and the wizard's profile is forgotten.
func (s *Service) Clear(user string) (*State, error) {
	s.mu.Lock()
	err := s.writeUpstreamLocked(placeholder(), nil, user)
	if err == nil {
		s.setUsingLocked("")
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.State(), nil
}

// setUsingLocked records which subscription node is in use.
func (s *Service) setUsingLocked(name string) {
	var sub subscription
	path := filepath.Join(s.opts.StateDir, subscriptionFile)
	if readJSON(path, &sub) == nil && sub.Using != name {
		sub.Using = name
		writeJSON(path, sub)
	}
}

// DeleteSubscription forgets the subscription and its nodes. The upstream in use stays.
func (s *Service) DeleteSubscription(user string) (*State, error) {
	s.mu.Lock()
	err := os.Remove(filepath.Join(s.opts.StateDir, subscriptionFile))
	s.mu.Unlock()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	log.Printf("audit: subscription deleted by %s", user)
	return s.State(), nil
}

// writeUpstreamLocked checks and writes upstream.json and the wizard's profile p, or with no
// profile removes it, then restarts sing-box, putting both back if it does not stay up.
func (s *Service) writeUpstreamLocked(upstream map[string]any, p *Profile, user string) error {
	data, err := json.MarshalIndent(upstream, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	entry, err := os.ReadFile(filepath.Join(s.opts.SingBoxDir, entryFile))
	if err != nil {
		return errors.New("sing-box 没有安装（没有 entry.json）")
	}
	trial, err := os.MkdirTemp(s.opts.StateDir, "check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(trial)
	for name, content := range map[string][]byte{entryFile: entry, upstreamFile: data} {
		if err := os.WriteFile(filepath.Join(trial, name), content, 0o600); err != nil {
			return err
		}
	}
	if err := s.sys.check(trial); err != nil {
		return fmt.Errorf("sing-box 不接受这个配置：%v", err)
	}
	path := filepath.Join(s.opts.SingBoxDir, upstreamFile)
	profilePath := filepath.Join(s.opts.ConfigDir, profileFile)
	oldUpstream, upstreamErr := os.ReadFile(path)
	oldProfile, profileErr := os.ReadFile(profilePath)
	if upstreamErr == nil {
		// Keep what was there, a hand-written upstream especially.
		if err := writeFileAtomic(path+".bak", oldUpstream, 0o600); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	what := "none"
	if p != nil {
		what = describe(*p)
		if err := writeJSON(profilePath, savedProfile{Profile: *p, Digest: digest(data)}); err != nil {
			return err
		}
	} else if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := s.restartLocked(); err != nil {
		restore := func(target string, content []byte, existed error) {
			if existed == nil {
				writeFileAtomic(target, content, 0o600)
			} else {
				os.Remove(target)
			}
		}
		restore(path, oldUpstream, upstreamErr)
		restore(profilePath, oldProfile, profileErr)
		s.restartLocked()
		log.Printf("audit: upstream %s by %s failed: %v", what, user, err)
		return fmt.Errorf("sing-box 用新上游没有启动起来，已恢复原来的上游：%v", err)
	}
	log.Printf("audit: upstream set to %s by %s", what, user)
	return nil
}

// restartLocked restarts sing-box and waits for it to stay up.
func (s *Service) restartLocked() error {
	if err := s.sys.unit("restart"); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		s.sleep(time.Second)
		if !s.sys.active() {
			return errors.New("sing-box 没有保持运行")
		}
	}
	return nil
}

// TestResult is how a request through an upstream went.
type TestResult struct {
	OK      bool   `json:"ok"`
	Status  int    `json:"status"`
	Millis  int64  `json:"millis"`
	Message string `json:"message"`
	URL     string `json:"url"`
}

// Test makes a request through a profile, or with none, through the current upstream, in a
// throwaway sing-box that leaves the running one alone.
func (s *Service) Test(p *Profile, url string) (*TestResult, error) {
	if url == "" {
		url = s.opts.TestURL
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("测试地址要以 http:// 或 https:// 开头")
	}
	var upstream map[string]any
	if p != nil {
		s.mu.Lock()
		var saved savedProfile
		if readJSON(filepath.Join(s.opts.ConfigDir, profileFile), &saved) == nil {
			p.KeepSecrets(&saved.Profile)
		}
		s.mu.Unlock()
		var err error
		if upstream, err = p.Upstream(); err != nil {
			return nil, err
		}
	} else {
		s.mu.Lock()
		kind, _, _ := s.upstreamLocked()
		data, err := os.ReadFile(filepath.Join(s.opts.SingBoxDir, upstreamFile))
		s.mu.Unlock()
		if kind == "none" || err != nil {
			return nil, errors.New("还没有配置上游")
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		upstream = map[string]any{"outbounds": doc["outbounds"], "endpoints": doc["endpoints"]}
	}
	status, elapsed, err := s.sys.probe(upstream, url)
	result := &TestResult{URL: url, Status: status, Millis: elapsed.Milliseconds()}
	switch {
	case err != nil:
		result.Message = err.Error()
	case status >= 200 && status < 400:
		result.OK = true
		result.Message = fmt.Sprintf("HTTP %d，%d 毫秒", status, result.Millis)
	default:
		result.Message = fmt.Sprintf("HTTP %d", status)
	}
	return result, nil
}

// Parse reads nodes from a sing-box configuration or share links, to fill the wizard.
func (s *Service) Parse(kind, text string) ([]Profile, error) {
	if len(text) > maxBody {
		return nil, errors.New("内容太大")
	}
	switch kind {
	case "json":
		return ParseSingBox(text)
	case "links":
		return ParseLinks(text)
	}
	return nil, fmt.Errorf("不认识的类型 %q", kind)
}

// Subscribe downloads a subscription and keeps its nodes for choosing.
func (s *Service) Subscribe(url string) (*State, error) {
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("订阅地址要以 http:// 或 https:// 开头")
	}
	body, err := s.sys.fetch(url)
	if err != nil {
		return nil, fmt.Errorf("下载订阅失败：%v", err)
	}
	nodes, err := ParseSubscription(body)
	if err != nil {
		return nil, fmt.Errorf("订阅内容：%v", err)
	}
	s.mu.Lock()
	var old subscription
	readJSON(filepath.Join(s.opts.StateDir, subscriptionFile), &old)
	sub := subscription{URL: url, Nodes: nodes, Fetched: time.Now()}
	if old.URL == url {
		sub.Using = old.Using
	}
	err = writeJSON(filepath.Join(s.opts.StateDir, subscriptionFile), sub)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.State(), nil
}

// SubscriptionNode returns a node of the subscription with its secrets, to fill the wizard.
// Secrets stay in the service: the node is applied by index.
func (s *Service) subscriptionNode(index int) (Profile, error) {
	var sub subscription
	if err := readJSON(filepath.Join(s.opts.StateDir, subscriptionFile), &sub); err != nil {
		return Profile{}, errors.New("还没有订阅")
	}
	if index < 0 || index >= len(sub.Nodes) {
		return Profile{}, errors.New("订阅里没有这个节点")
	}
	return sub.Nodes[index], nil
}

// UseSubscriptionNode applies a node of the subscription and remembers it by name.
func (s *Service) UseSubscriptionNode(index int, user string) (*State, error) {
	node, err := s.subscriptionNode(index)
	if err != nil {
		return nil, err
	}
	if _, err := s.Apply(node, user); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.setUsingLocked(node.Name)
	s.mu.Unlock()
	return s.State(), nil
}

// UpdateSubscription downloads the subscription again and re-applies the node in use, found by
// its name, if it changed.
func (s *Service) UpdateSubscription(user string) (*State, error) {
	var sub subscription
	if err := readJSON(filepath.Join(s.opts.StateDir, subscriptionFile), &sub); err != nil {
		return nil, errors.New("还没有订阅")
	}
	if _, err := s.Subscribe(sub.URL); err != nil {
		return nil, err
	}
	if sub.Using == "" {
		return s.State(), nil
	}
	var fresh subscription
	readJSON(filepath.Join(s.opts.StateDir, subscriptionFile), &fresh)
	for i, node := range fresh.Nodes {
		if node.Name == sub.Using {
			return s.UseSubscriptionNode(i, user)
		}
	}
	return nil, fmt.Errorf("订阅里已经没有正在使用的节点 %q，上游没有改动", sub.Using)
}

// TestSubscriptionNode tests a node of the subscription.
func (s *Service) TestSubscriptionNode(index int, url string) (*TestResult, error) {
	node, err := s.subscriptionNode(index)
	if err != nil {
		return nil, err
	}
	return s.Test(&node, url)
}

// Unit starts, stops or restarts sing-box.
func (s *Service) Unit(action, user string) (*State, error) {
	switch action {
	case "start", "stop", "restart":
	default:
		return nil, errors.New("不认识的操作")
	}
	s.mu.Lock()
	err := s.sys.unit(action)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	log.Printf("audit: sing-box %s by %s", action, user)
	s.sleep(time.Second)
	return s.State(), nil
}

// fetchLimited downloads at most limit bytes.
func fetchLimited(ctx context.Context, url string, limit int64) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// Providers answer a sing-box client with a sing-box configuration.
	request.Header.Set("User-Agent", "sing-box")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", errors.New("订阅内容超过 4 MB")
	}
	return string(data), nil
}

// freePort finds a loopback port for a throwaway sing-box.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
