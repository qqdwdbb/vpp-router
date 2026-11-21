package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gate "vpp.local/vpp-egress-gate"
)

// fakeAdminSystem records what applying a change asked of the machine.
type fakeAdminSystem struct {
	calls     []string
	checkErr  error
	readyErr  error
	stopErr   error
	flushErr  error
	startErr  error
	routes    []adminRoute
	status    *gate.DefaultRouteStatus
	routesErr error
}

func (f *fakeAdminSystem) check() error   { f.calls = append(f.calls, "check"); return f.checkErr }
func (f *fakeAdminSystem) sync() error    { f.calls = append(f.calls, "sync"); return nil }
func (f *fakeAdminSystem) restart() error { f.calls = append(f.calls, "restart"); return nil }
func (f *fakeAdminSystem) ready() error   { f.calls = append(f.calls, "ready"); return f.readyErr }
func (f *fakeAdminSystem) stop() error    { f.calls = append(f.calls, "stop"); return f.stopErr }
func (f *fakeAdminSystem) flush() error   { f.calls = append(f.calls, "flush"); return f.flushErr }
func (f *fakeAdminSystem) start() error   { f.calls = append(f.calls, "start"); return f.startErr }
func (f *fakeAdminSystem) ledger() (gateLedger, error) {
	return gateLedger{Owned: f.routes, Default: f.status}, f.routesErr
}

type adminFixture struct {
	dir, routes, mediafixture, textfixture string
	sys                                    *fakeAdminSystem
	admin                                  *Admin
	now                                    *time.Time
	opts                                   AdminOptions
}

// newAdminFixture mirrors a real rule file: IPv4 and IPv6 rules sharing a list, a proxy exit
// with Fake-IP attributes, an IPv4-only tunnel and a dual-stack exit.
func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := &adminFixture{dir: t.TempDir(), sys: &fakeAdminSystem{}}
	f.routes = filepath.Join(f.dir, "domains.json")
	f.mediafixture = filepath.Join(f.dir, "mediafixture.domains")
	f.textfixture = filepath.Join(f.dir, "textfixture.domains")
	vpn := filepath.Join(f.dir, "vpn.domains")
	static := filepath.Join(f.dir, "static.ipv4")
	for path, content := range map[string]string{f.mediafixture: "# streaming\nvideo.example.net\n\nedgevideo.example.net\n", f.textfixture: "docs.example.org\n", vpn: "corp.example\n", static: "1.2.3.0/24\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	doc := map[string]any{"fakeip_ttl": 604800, "routes": []any{
		map[string]any{"name": "mediafixture", "interface": "tap1", "via": "172.31.0.2", "fib_table": 0, "domain_files": []any{f.mediafixture}, "dns_upstream": []any{"127.0.0.1", 5354}, "fakeip_range": "198.18.0.0/15"},
		map[string]any{"name": "mediafixture6", "interface": "tap1", "via": "fd76::2", "fib_table": 0, "domain_files": []any{f.mediafixture}, "dns_upstream": []any{"127.0.0.1", 5354}, "fakeip_range": "2001:2::/48"},
		map[string]any{"name": "textfixture", "interface": "wg1", "via": "10.62.30.1", "fib_table": 0, "domain_files": []any{f.textfixture}},
		map[string]any{"name": "vpn", "interface": "loop10", "via": "10.61.50.1", "fib_table": 0, "domain_files": []any{vpn}},
		map[string]any{"name": "vpn6", "interface": "loop10", "via": "fd00::1", "fib_table": 0, "domain_files": []any{vpn}},
		map[string]any{"name": "pinned", "interface": "tap1", "via": "172.31.0.2", "fib_table": 0, "domain_files": []any{f.textfixture + ".unused"}, "ip_range_files": []any{static}},
	}}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(f.routes, data, 0o640); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(f.dir, "entry.json")
	entry, _ := json.Marshal(map[string]any{"domain_routes_file": f.routes})
	if err := os.WriteFile(config, entry, 0o644); err != nil {
		t.Fatal(err)
	}
	f.opts = AdminOptions{Config: config, StateDir: filepath.Join(f.dir, "state"), ListDir: f.dir, Confirm: time.Minute}
	admin, err := NewAdmin(f.opts, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	admin.now = func() time.Time { return now }
	f.admin, f.now = admin, &now
	t.Cleanup(func() {
		if admin.timer != nil {
			admin.timer.Stop()
		}
	})
	return f
}

func (f *adminFixture) group(t *testing.T, id string) AdminGroup {
	t.Helper()
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range state.Groups {
		if group.ID == id {
			return group
		}
	}
	t.Fatalf("no group %s", id)
	return AdminGroup{}
}

func (f *adminFixture) rule(t *testing.T, name string) map[string]any {
	t.Helper()
	doc, err := readJSONObject(f.routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range doc["routes"].([]any) {
		if rule := item.(map[string]any); rule["name"] == name {
			return rule
		}
	}
	t.Fatalf("no rule %s", name)
	return nil
}

func TestGroupsShareTheirDomainSource(t *testing.T) {
	f := newAdminFixture(t)
	group := f.group(t, "mediafixture")
	if strings.Join(group.Rules, ",") != "mediafixture,mediafixture6" || len(group.Families) != 2 || group.Exit != "tap1" || group.Domains != 2 {
		t.Fatalf("group = %+v", group)
	}
	state, _ := f.admin.State()
	if len(state.Groups) != 4 || len(state.Exits) != 3 {
		t.Fatalf("state = %+v", state)
	}
}

func TestOptionsNeedANextHopForEveryFamily(t *testing.T) {
	f := newAdminFixture(t)
	if options := f.group(t, "mediafixture").Options; len(options) != 1 || options[0] != "loop10" {
		t.Fatalf("a dual-stack group was offered %v; wg1 has no IPv6 next hop", options)
	}
	if options := strings.Join(f.group(t, "textfixture").Options, ","); options != "tap1,loop10" {
		t.Fatalf("options = %s", options)
	}
}

func TestSwitchCarriesTheExitsAttributes(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SwitchExit("textfixture", "tap1", "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "textfixture")
	if rule["interface"] != "tap1" || rule["via"] != "172.31.0.2" || rule["fakeip_range"] != "198.18.0.0/15" || rule["dns_upstream"] == nil {
		t.Fatalf("rule = %v", rule)
	}
	if files := rule["domain_files"].([]any); files[0] != f.textfixture {
		t.Fatalf("the domain list changed: %v", files)
	}
	if strings.Join(f.sys.calls, ",") != "check,sync,restart,ready" {
		t.Fatalf("calls = %v", f.sys.calls)
	}
}

func TestSwitchLeavingFakeIPDropsItsAttributes(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SwitchExit("mediafixture", "loop10", "admin"); err != nil {
		t.Fatal(err)
	}
	four, six := f.rule(t, "mediafixture"), f.rule(t, "mediafixture6")
	if four["via"] != "10.61.50.1" || six["via"] != "fd00::1" || four["fakeip_range"] != nil || four["dns_upstream"] != nil {
		t.Fatalf("rules = %v %v", four, six)
	}
}

func TestSwitchMovesStaticRanges(t *testing.T) {
	f := newAdminFixture(t)
	if options := strings.Join(f.group(t, "pinned").Options, ","); options != "wg1,loop10" {
		t.Fatalf("options = %s", options)
	}
	if _, err := f.admin.SwitchExit("pinned", "wg1", "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "pinned")
	if rule["interface"] != "wg1" || rule["via"] != "10.62.30.1" {
		t.Fatalf("rule = %v", rule)
	}
	if files := rule["ip_range_files"].([]any); len(files) != 1 || filepath.Base(files[0].(string)) != "static.ipv4" {
		t.Fatalf("the ranges changed: %v", files)
	}
	if strings.Join(f.sys.calls, ",") != "check,sync,restart,ready" {
		t.Fatalf("calls = %v", f.sys.calls)
	}
}

func describeRules(rules []map[string]any, members ...int) AdminGroup {
	profiles := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		profiles = append(profiles, ruleAttributes(rule))
	}
	return describeGroup(rules, profiles, members)
}

// A TPROXY listener takes real addresses too, so ranges may go to a Fake-IP exit.
func TestStaticRangesMayUseFakeIPExits(t *testing.T) {
	ranges := filepath.Join(t.TempDir(), "r.ipv4")
	if err := os.WriteFile(ranges, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := []map[string]any{
		{"name": "gate", "interface": "tap1", "via": "172.31.0.2", "domains": []any{"a.example"}, "fakeip_range": "198.18.0.0/15", "tproxy_port": 2082},
		{"name": "firewall", "interface": "tap2", "via": "172.31.1.2", "domains": []any{"b.example"}, "fakeip_range": "198.20.0.0/15"},
		{"name": "tunnel", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"c.example"}},
		{"name": "ranges", "interface": "wg2", "via": "10.2.5.1", "ip_range_files": []any{ranges}},
		{"name": "names", "interface": "wg2", "via": "10.2.5.1", "domains": []any{"d.example"}},
	}
	if options := strings.Join(describeRules(rules, 3).Options, ","); options != "tap1,tap2,wg1" {
		t.Fatalf("a group with ranges was offered %s", options)
	}
	if options := strings.Join(describeRules(rules, 4).Options, ","); options != "tap1,tap2,wg1" {
		t.Fatalf("a group with only names was offered %s", options)
	}
}

// Gate would refuse to start with these, so the switch must not get as far as restarting it.
func TestStaticRangeOverlappingAnotherRulesPoolStaysPut(t *testing.T) {
	ranges := filepath.Join(t.TempDir(), "r.ipv4")
	write := func(content string) {
		if err := os.WriteFile(ranges, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rules := []map[string]any{
		{"name": "mediafixture", "interface": "tap1", "via": "172.31.0.2", "domains": []any{"a.example"}, "fakeip_range": "198.18.0.0/15"},
		{"name": "sampleproxy", "interface": "tap1", "via": "172.31.0.2", "domains": []any{"b.example"}, "fakeip_range": "198.18.0.0/15", "ip_range_files": []any{ranges}},
		{"name": "tunnel", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"c.example"}},
	}
	write("198.18.0.0/15\n203.0.113.0/24\n")
	group := describeRules(rules, 1)
	if len(group.Options) != 0 || !strings.Contains(group.Locked, "198.18.0.0/15") || !strings.Contains(group.Locked, "mediafixture") {
		t.Fatalf("group = %+v", group)
	}
	write("198.19.0.1-198.19.0.2\n")
	if group := describeRules(rules, 1); len(group.Options) != 0 || group.Locked == "" {
		t.Fatalf("a range form was missed: %+v", group)
	}
	write("203.0.113.0/24\n")
	if group := describeRules(rules, 1); strings.Join(group.Options, ",") != "wg1" || group.Locked != "" {
		t.Fatalf("group = %+v", group)
	}
}

func TestLastRuleOnAPoolCanTakeItsRangesAway(t *testing.T) {
	ranges := filepath.Join(t.TempDir(), "r.ipv4")
	if err := os.WriteFile(ranges, []byte("198.18.0.0/15\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := []map[string]any{
		{"name": "sampleproxy", "interface": "tap1", "via": "172.31.0.2", "domains": []any{"b.example"}, "fakeip_range": "198.18.0.0/15", "ip_range_files": []any{ranges}},
		{"name": "tunnel", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"c.example"}},
	}
	if group := describeRules(rules, 0); strings.Join(group.Options, ",") != "wg1" || group.Locked != "" {
		t.Fatalf("group = %+v", group)
	}
}

func TestSwitchRefusals(t *testing.T) {
	f := newAdminFixture(t)
	for name, attempt := range map[string][2]string{
		"unknown group":    {"nope", "tap1"},
		"same exit":        {"textfixture", "wg1"},
		"no IPv6 next hop": {"mediafixture", "wg1"},
		"unknown exit":     {"textfixture", "eth9"},
	} {
		if _, err := f.admin.SwitchExit(attempt[0], attempt[1], "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused change reached the system: %v", f.sys.calls)
	}
}

func TestReorderSetsPriorityByGroup(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.Reorder([]string{"vpn", "mediafixture", "textfixture", "pinned"}, "admin"); err != nil {
		t.Fatal(err)
	}
	doc, _ := readJSONObject(f.routes)
	var names []string
	for _, item := range doc["routes"].([]any) {
		names = append(names, item.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "vpn,vpn6,mediafixture,mediafixture6,textfixture,pinned" {
		t.Fatalf("order = %v", names)
	}
}

func TestReorderRefusals(t *testing.T) {
	f := newAdminFixture(t)
	for name, order := range map[string][]string{
		"missing a group": {"vpn", "mediafixture", "textfixture"},
		"unknown group":   {"vpn", "mediafixture", "textfixture", "nope"},
		"duplicate":       {"vpn", "vpn", "textfixture", "pinned"},
		"same order":      {"mediafixture", "textfixture", "vpn", "pinned"},
	} {
		if _, err := f.admin.Reorder(order, "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused change reached the system: %v", f.sys.calls)
	}
}

func TestEditFileKeepsCommentsAndValidates(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.EditFile(f.mediafixture, []string{"Speed.EXAMPLE.NET.", "video.example.net"}, []string{"EDGEVIDEO.example.net"}, "admin"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f.mediafixture)
	if string(data) != "# streaming\nvideo.example.net\n\nspeed.example.net\n" {
		t.Fatalf("file = %q", data)
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string][2][]string{
		"invalid domain": {{"bad domain!"}, nil},
		"nothing to do":  {{"video.example.net"}, {"missing.example"}},
	} {
		if _, err := f.admin.EditFile(f.mediafixture, attempt[0], attempt[1], "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOnlyFilesRulesUseCanBeTouched(t *testing.T) {
	f := newAdminFixture(t)
	secret := filepath.Join(f.dir, "shadow")
	os.WriteFile(secret, []byte("root\n"), 0o600)
	if _, err := f.admin.FileDomains(secret, ""); err == nil {
		t.Fatal("read a file no rule uses")
	}
	if _, err := f.admin.EditFile(secret, []string{"a.example"}, nil, "admin"); err == nil {
		t.Fatal("wrote a file no rule uses")
	}
	if _, err := f.admin.FileDomains(f.mediafixture+"/../"+filepath.Base(secret), ""); err == nil {
		t.Fatal("a path outside the rules was accepted")
	}
	if data, _ := os.ReadFile(secret); string(data) != "root\n" {
		t.Fatalf("file = %q", data)
	}
}

func TestFileDomainsSearchAndLimit(t *testing.T) {
	f := newAdminFixture(t)
	var content strings.Builder
	for i := 0; i < adminDomainLimit+50; i++ {
		content.WriteString("host")
		content.WriteString(strings.Repeat("x", i%5+1))
		content.WriteString(".example\n")
	}
	os.WriteFile(f.textfixture, []byte(content.String()), 0o644)
	result, err := f.admin.FileDomains(f.textfixture, "")
	if err != nil || result["total"] != adminDomainLimit+50 || len(result["domains"].([]string)) != adminDomainLimit {
		t.Fatalf("%v %v", result["total"], err)
	}
	result, _ = f.admin.FileDomains(f.textfixture, "HOSTxxxxx")
	if result["matched"].(int) != (adminDomainLimit+50)/5 {
		t.Fatalf("matched = %v", result["matched"])
	}
}

func TestUnconfirmedChangeIsRolledBack(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.routes)
	state, err := f.admin.SwitchExit("textfixture", "tap1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || state.SecondsRemaining != 60 {
		t.Fatalf("state = %+v", state)
	}
	if _, err := f.admin.SwitchExit("vpn", "tap1", "admin"); err == nil {
		t.Fatal("a second change started while one was pending")
	}
	f.sys.calls = nil
	f.admin.expire() // not due yet
	if len(f.sys.calls) != 0 {
		t.Fatal("rolled back early")
	}
	*f.now = f.now.Add(time.Minute)
	f.admin.expire()
	after, _ := os.ReadFile(f.routes)
	if string(before) != string(after) {
		t.Fatalf("not restored: %s", after)
	}
	if strings.Join(f.sys.calls, ",") != "sync,restart,ready" {
		t.Fatalf("calls = %v", f.sys.calls)
	}
	state, _ = f.admin.State()
	if state.Pending != nil || state.Last.Outcome != "rolled-back" {
		t.Fatalf("state = %+v", state)
	}
	if info, _ := os.Stat(f.routes); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestConfirmKeepsTheChange(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.SwitchExit("textfixture", "tap1", "admin")
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.calls = nil
	*f.now = f.now.Add(time.Hour)
	f.admin.expire()
	if f.rule(t, "textfixture")["interface"] != "tap1" || len(f.sys.calls) != 0 {
		t.Fatalf("calls = %v", f.sys.calls)
	}
	entries, _ := os.ReadDir(f.opts.StateDir)
	for _, entry := range entries {
		if entry.Name() != exitsFile {
			t.Fatalf("left behind: %v", entries)
		}
	}
	if err := f.admin.Confirm("admin"); err == nil {
		t.Fatal("confirmed nothing")
	}
}

func TestManualRollback(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.SwitchExit("textfixture", "tap1", "admin")
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if f.rule(t, "textfixture")["interface"] != "wg1" {
		t.Fatal("not restored")
	}
}

func TestRefusedConfigurationChangesNothing(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.mediafixture)
	f.sys.checkErr = errors.New("bad list")
	_, err := f.admin.EditFile(f.mediafixture, []string{"new.example"}, nil, "admin")
	if err == nil || !strings.Contains(err.Error(), "bad list") {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(f.mediafixture)
	if string(before) != string(after) || strings.Join(f.sys.calls, ",") != "check" {
		t.Fatalf("calls = %v, file = %q", f.sys.calls, after)
	}
}

func TestGateNotComingBackRollsBackAtOnce(t *testing.T) {
	f := newAdminFixture(t)
	f.sys.readyErr = errors.New("no answer")
	_, err := f.admin.SwitchExit("textfixture", "tap1", "admin")
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if f.rule(t, "textfixture")["interface"] != "wg1" {
		t.Fatal("not restored")
	}
	state, _ := f.admin.State()
	if state.Pending != nil || state.Last.Outcome != "rollback-failed" {
		t.Fatalf("state = %+v", state.Last)
	}
}

func TestRestartDuringPendingIsResolved(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.SwitchExit("textfixture", "tap1", "admin")
	f.admin.timer.Stop()
	// The deadline is on the fixture's clock, in the past for a new process.
	sys := &fakeAdminSystem{}
	restarted, err := NewAdmin(f.opts, sys)
	if err != nil {
		t.Fatal(err)
	}
	if f.rule(t, "textfixture")["interface"] != "wg1" || restarted.last.Outcome != "rolled-back" {
		t.Fatalf("rule = %v, last = %+v", f.rule(t, "textfixture"), restarted.last)
	}
}

func TestAdminAPI(t *testing.T) {
	f := newAdminFixture(t)
	handler := f.admin.Handler()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Panel-User", "alice")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/gate/state", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mediafixture"`) {
		t.Fatalf("state = %d %s", w.Code, w.Body)
	}
	if w := call("POST", "/gate/order", `{"order":["vpn","mediafixture","textfixture","pinned"]}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"pending":{`) {
		t.Fatalf("order = %d %s", w.Code, w.Body)
	}
	if f.admin.pending.User != "alice" {
		t.Fatalf("user = %s", f.admin.pending.User)
	}
	if w := call("POST", "/gate/switch", `{"group":"textfixture","exit":"tap1"}`); w.Code != http.StatusConflict {
		t.Fatalf("second change = %d", w.Code)
	}
	if w := call("POST", "/gate/confirm", ""); w.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", w.Code, w.Body)
	}
	if w := call("POST", "/gate/file", `{"path":"`+f.mediafixture+`","add":["a.example"]}`); w.Code != http.StatusOK {
		t.Fatalf("file = %d %s", w.Code, w.Body)
	}
	if w := call("POST", "/gate/rollback", ""); w.Code != http.StatusOK {
		t.Fatalf("rollback = %d %s", w.Code, w.Body)
	}
	if w := call("GET", "/gate/file?path="+f.mediafixture+"&q=edgev", ""); !strings.Contains(w.Body.String(), "edgevideo.example.net") {
		t.Fatalf("file = %s", w.Body)
	}
	if w := call("POST", "/gate/switch", "not json"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", w.Code)
	}
}

func TestAnExitNobodyUsesCanStillBeChosen(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SwitchExit("textfixture", "tap1", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if options := strings.Join(f.group(t, "textfixture").Options, ","); !strings.Contains(options, "wg1") {
		t.Fatalf("the exit it left is gone: %s", options)
	}
	// It has to survive the service restarting too.
	restarted, err := NewAdmin(f.opts, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	f.admin = restarted
	if _, err := restarted.SwitchExit("textfixture", "wg1", "admin"); err != nil {
		t.Fatal(err)
	}
	if restarted.timer != nil {
		restarted.timer.Stop()
	}
	rule := f.rule(t, "textfixture")
	if rule["interface"] != "wg1" || rule["via"] != "10.62.30.1" || rule["fakeip_range"] != nil {
		t.Fatalf("rule = %v", rule)
	}
}

func (f *adminFixture) ruleNames(t *testing.T) string {
	t.Helper()
	doc, err := readJSONObject(f.routes)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, item := range doc["routes"].([]any) {
		names = append(names, item.(map[string]any)["name"].(string))
	}
	return strings.Join(names, ",")
}

func TestUploadCreatesAnUnusedFileWithoutRestartingGate(t *testing.T) {
	f := newAdminFixture(t)
	state, err := f.admin.UploadFile("new.domains", "# mine\r\nExample.COM.\nexample.com\n\nb.example\n", false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(f.dir, "new.domains"))
	if string(data) != "# mine\nexample.com\n\nb.example\n" {
		t.Fatalf("file = %q", data)
	}
	if len(f.sys.calls) != 0 || state.Pending != nil {
		t.Fatalf("calls = %v, pending = %v", f.sys.calls, state.Pending)
	}
	found := false
	for _, file := range state.Files {
		if file.Name == "new.domains" && file.Domains == 2 && len(file.UsedBy) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("files = %+v", state.Files)
	}
}

func TestUploadRefusals(t *testing.T) {
	f := newAdminFixture(t)
	for name, attempt := range map[string][2]string{
		"path in the name": {"../evil.domains", "a.example\n"},
		"wrong suffix":     {"evil.conf", "a.example\n"},
		"hidden file":      {".x.domains", "a.example\n"},
		"bad line":         {"bad.domains", "good.example\nnot a domain\n"},
		"already exists":   {"mediafixture.domains", "a.example\n"},
	} {
		if _, err := f.admin.UploadFile(attempt[0], attempt[1], false, "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "bad.domains")); err == nil {
		t.Fatal("a refused upload left a file")
	}
}

func TestReplacingAFileInUseGoesThroughConfirmation(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.mediafixture)
	state, err := f.admin.UploadFile("mediafixture.domains", "replaced.example\n", true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || strings.Join(f.sys.calls, ",") != "check,sync,restart,ready" {
		t.Fatalf("pending %v, calls %v", state.Pending, f.sys.calls)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(f.mediafixture); string(after) != string(before) {
		t.Fatalf("not restored: %q", after)
	}
}

func TestAddRuleCopiesTheExitForEachFamily(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.UploadFile("new.domains", "a.example\n", false, "admin")
	file := filepath.Join(f.dir, "new.domains")
	if _, err := f.admin.AddRule("media", "tap1", nil, file, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.ruleNames(t); got != "mediafixture,mediafixture6,textfixture,vpn,vpn6,pinned,media,media6" {
		t.Fatalf("names = %s", got)
	}
	four, six := f.rule(t, "media"), f.rule(t, "media6")
	if four["interface"] != "tap1" || four["via"] != "172.31.0.2" || four["fakeip_range"] != "198.18.0.0/15" || six["via"] != "fd76::2" {
		t.Fatalf("rules = %v %v", four, six)
	}
	if four["domain_files"].([]any)[0] != file {
		t.Fatalf("file = %v", four["domain_files"])
	}
	if group := f.group(t, "media"); len(group.Families) != 2 || group.Domains != 1 {
		t.Fatalf("group = %+v", group)
	}
}

func TestAddRuleWithMultipleListFiles(t *testing.T) {
	f := newAdminFixture(t)
	domains := f.upload(t, "more.domains", "more.example\n")
	ranges := f.upload(t, "more.ranges", "203.0.113.0/24\n")
	secondRanges := f.upload(t, "other.ranges", "198.51.100.0/24\n")
	if _, err := f.admin.AddRuleWithFiles("multi", "loop10", []int{4}, []string{f.textfixture, domains}, []string{ranges, secondRanges}, nil, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "multi")
	domainFiles := rule["domain_files"].([]any)
	if len(domainFiles) != 2 || domainFiles[0] != f.textfixture || domainFiles[1] != domains {
		t.Fatalf("domain files = %v", domainFiles)
	}
	rangeFiles := rule["ip_range_files"].([]any)
	if len(rangeFiles) != 2 || rangeFiles[0] != ranges || rangeFiles[1] != secondRanges {
		t.Fatalf("range files = %v", rangeFiles)
	}
}

func TestAddRuleOneFamily(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.AddRule("only6", "tap1", []int{6}, f.textfixture, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "only6"); rule["via"] != "fd76::2" {
		t.Fatalf("rule = %v", rule)
	}
}

func TestAddRuleRefusals(t *testing.T) {
	f := newAdminFixture(t)
	for name, attempt := range map[string]struct {
		name, exit string
		families   []int
		file       string
	}{
		"bad name":        {"a b", "tap1", nil, f.textfixture},
		"taken name":      {"textfixture", "tap1", []int{4}, f.textfixture},
		"generated taken": {"mediafixture", "tap1", nil, f.textfixture},
		"unknown exit":    {"x", "eth9", nil, f.textfixture},
		"no IPv6 hop":     {"x", "wg1", []int{6}, f.textfixture},
		"unmanaged file":  {"x", "tap1", nil, "/etc/passwd"},
	} {
		if _, err := f.admin.AddRule(attempt.name, attempt.exit, attempt.families, attempt.file, "", "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused rule reached the system: %v", f.sys.calls)
	}
}

func TestDeleteRuleRemovesTheGroupAndCanBeRolledBack(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.DeleteRule("mediafixture", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.ruleNames(t); got != "textfixture,vpn,vpn6,pinned" {
		t.Fatalf("names = %s", got)
	}
	if _, err := os.Stat(f.mediafixture); err != nil {
		t.Fatalf("the list file went with the rule: %v", err)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.ruleNames(t); got != "mediafixture,mediafixture6,textfixture,vpn,vpn6,pinned" {
		t.Fatalf("names = %s", got)
	}
	if _, err := f.admin.DeleteRule("nope", "admin"); err == nil {
		t.Fatal("deleted an unknown group")
	}
}

func TestDeleteFileOnlyWhenUnused(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.DeleteFile(f.mediafixture, "admin"); err == nil || !strings.Contains(err.Error(), "mediafixture") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.admin.DeleteFile("/etc/passwd", "admin"); err == nil {
		t.Fatal("deleted an unmanaged file")
	}
	f.admin.UploadFile("old.domains", "a.example\n", false, "admin")
	path := filepath.Join(f.dir, "old.domains")
	if _, err := f.admin.DeleteFile(path, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("still there")
	}
	copies, _ := filepath.Glob(filepath.Join(f.opts.StateDir, "deleted", "old.domains.*"))
	if len(copies) != 1 || len(f.sys.calls) != 0 {
		t.Fatalf("copies %v, calls %v", copies, f.sys.calls)
	}
}

func TestEditingAnUnusedFileDoesNotRestartGate(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.UploadFile("idle.domains", "a.example\n", false, "admin")
	path := filepath.Join(f.dir, "idle.domains")
	state, err := f.admin.EditFile(path, []string{"b.example"}, []string{"a.example"}, "admin")
	if err != nil || state.Pending != nil || len(f.sys.calls) != 0 {
		t.Fatalf("%v, pending %v, calls %v", err, state, f.sys.calls)
	}
	if data, _ := os.ReadFile(path); string(data) != "b.example\n" {
		t.Fatalf("file = %q", data)
	}
}

func TestNothingIsWrittenWhileAChangeIsPending(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.SwitchExit("textfixture", "tap1", "admin")
	if _, err := f.admin.UploadFile("x.domains", "a.example\n", false, "admin"); err == nil {
		t.Fatal("an upload went through")
	}
	if _, err := f.admin.AddRule("y", "tap1", nil, f.textfixture, "", "admin"); err == nil {
		t.Fatal("a rule went through")
	}
	if _, err := f.admin.DeleteFile(f.mediafixture, "admin"); err == nil {
		t.Fatal("a delete went through")
	}
}

func TestAdminAPIForRulesAndFiles(t *testing.T) {
	f := newAdminFixture(t)
	handler := f.admin.Handler()
	call := func(path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return w
	}
	if w := call("/gate/upload", `{"name":"api.domains","content":"a.example\n"}`); w.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
	if w := call("/gate/upload", `{"name":"api-more.domains","content":"b.example\n"}`); w.Code != http.StatusOK {
		t.Fatalf("second upload = %d %s", w.Code, w.Body)
	}
	file := filepath.Join(f.dir, "api.domains")
	more := filepath.Join(f.dir, "api-more.domains")
	if w := call("/gate/rule", `{"name":"api","exit":"wg1","file":["`+file+`","`+more+`"]}`); w.Code != http.StatusOK {
		t.Fatalf("rule = %d %s", w.Code, w.Body)
	}
	if w := call("/gate/confirm", ""); w.Code != http.StatusOK {
		t.Fatalf("confirm = %d", w.Code)
	}
	if w := call("/gate/rule/delete", `{"group":"api"}`); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if w := call("/gate/confirm", ""); w.Code != http.StatusOK {
		t.Fatalf("confirm = %d", w.Code)
	}
	if w := call("/gate/file/delete", `{"path":"`+file+`"}`); w.Code != http.StatusOK {
		t.Fatalf("file delete = %d %s", w.Code, w.Body)
	}
}

func (f *adminFixture) upload(t *testing.T, name, content string) string {
	t.Helper()
	if _, err := f.admin.UploadFile(name, content, false, "admin"); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(f.dir, name)
}

func TestRangeFilesAreManaged(t *testing.T) {
	f := newAdminFixture(t)
	path := f.upload(t, "office.ranges", "# office\r\n203.0.113.5\n203.0.113.0/24\n203.0.113.0/24\n198.51.100.1 - 198.51.100.9 # lab\n2001:DB8::/32\n")
	data, _ := os.ReadFile(path)
	if string(data) != "# office\n203.0.113.5/32\n203.0.113.0/24\n198.51.100.1-198.51.100.9\n2001:db8::/32\n" {
		t.Fatalf("file = %q", data)
	}
	state, _ := f.admin.State()
	kinds := map[string]string{}
	for _, file := range state.Files {
		kinds[file.Name] = file.Kind
	}
	if kinds["office.ranges"] != "ranges" || kinds["static.ipv4"] != "ranges" || kinds["mediafixture.domains"] != "domains" {
		t.Fatalf("kinds = %v", kinds)
	}
	if _, err := f.admin.EditFile(path, []string{"192.0.2.0/24"}, []string{"203.0.113.5"}, "admin"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "203.0.113.5") || !strings.Contains(string(data), "192.0.2.0/24") {
		t.Fatalf("file = %q", data)
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("an unused file reached the system: %v", f.sys.calls)
	}
}

func TestRangeFilesRefuseWhatGateWouldNot(t *testing.T) {
	f := newAdminFixture(t)
	for _, content := range []string{"example.com\n", "0.0.0.0/0\n", "1.2.3.4/24\n", "9.9.9.9-1.1.1.1\n", "1.1.1.1-::1\n", "0.0.0.0-255.255.255.255\n"} {
		if _, err := f.admin.UploadFile("bad.ranges", content, false, "admin"); err == nil {
			t.Errorf("%q accepted", content)
		}
	}
	if _, err := f.admin.UploadFile("list.domains", "1.2.3.0/24\n", false, "admin"); err == nil {
		t.Error("a prefix was accepted as a domain")
	}
}

func TestAddRuleWithOnlyRanges(t *testing.T) {
	f := newAdminFixture(t)
	path := f.upload(t, "office.ranges", "203.0.113.0/24\n")
	if _, err := f.admin.AddRule("office", "loop10", nil, "", path, "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "office")
	if rule["via"] != "10.61.50.1" || rule["domain_files"] != nil || rule["ip_range_files"].([]any)[0] != path {
		t.Fatalf("rule = %v", rule)
	}
	if group := f.group(t, "office"); group.Ranges != 1 || group.Domains != 0 || len(group.Families) != 1 {
		t.Fatalf("group = %+v", group)
	}
}

func TestAddRuleRangesWithDomainsOnSeparateFamilies(t *testing.T) {
	f := newAdminFixture(t)
	path := f.upload(t, "office.ranges", "2001:db8::/32\n")
	if _, err := f.admin.AddRule("office", "loop10", nil, f.textfixture, path, "admin"); err != nil {
		t.Fatal(err)
	}
	if four, six := f.rule(t, "office"), f.rule(t, "office6"); four["ip_range_files"] != nil || six["ip_range_files"] == nil || six["via"] != "fd00::1" {
		t.Fatalf("rules = %v %v", four, six)
	}
}

func TestAddRuleRangeRefusals(t *testing.T) {
	f := newAdminFixture(t)
	mixed := f.upload(t, "mixed.ranges", "203.0.113.0/24\n2001:db8::/32\n")
	six := f.upload(t, "six.ranges", "2001:db8::/32\n")
	empty := f.upload(t, "empty.ranges", "# nothing\n")
	pool := f.upload(t, "pool.ranges", "198.18.1.0/24\n")
	for name, attempt := range map[string]struct {
		exit         string
		families     []int
		file, ranges string
	}{
		"no source":           {exit: "loop10"},
		"mixed on split exit": {exit: "loop10", ranges: mixed},
		"no such family":      {exit: "wg1", ranges: six},
		"family not selected": {exit: "loop10", families: []int{4}, file: f.textfixture, ranges: six},
		"no usable line":      {exit: "loop10", ranges: empty},
		"overlaps a pool":     {exit: "loop10", ranges: pool},
		"ranges as a domain":  {exit: "loop10", file: six},
		"domains as ranges":   {exit: "loop10", ranges: f.textfixture},
	} {
		if _, err := f.admin.AddRule("new", attempt.exit, attempt.families, attempt.file, attempt.ranges, "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused rule reached the system: %v", f.sys.calls)
	}
}

func TestAddRuleRangesOnFakeIPTProxyExit(t *testing.T) {
	f := newAdminFixture(t)
	doc, _ := readJSONObject(f.routes)
	doc["routes"] = append(doc["routes"].([]any), map[string]any{"name": "proxied", "interface": "tap9", "via": "172.31.9.2", "domains": []any{"a.example"}, "dns_upstream": []any{"127.0.0.1", 5354}, "fakeip_range": "198.20.0.0/15", "tproxy_port": 2082})
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(f.routes, data, 0o640); err != nil {
		t.Fatal(err)
	}
	path := f.upload(t, "office.ranges", "203.0.113.0/24\n")
	if _, err := f.admin.AddRule("office", "tap9", nil, "", path, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "office"); rule["tproxy_port"] != float64(2082) || len(anyStrings(rule["ip_range_files"])) != 1 {
		t.Fatalf("rule: %+v", rule)
	}
}

func TestEditUsedRangeFileIsCheckedBeforeRestart(t *testing.T) {
	f := newAdminFixture(t)
	path := filepath.Join(f.dir, "static.ipv4")
	if _, err := f.admin.EditFile(path, []string{"2001:db8::/32"}, nil, "admin"); err == nil {
		t.Error("a family the rule has no next hop for was accepted")
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused edit reached the system: %v", f.sys.calls)
	}
	// pinned shares tap1 with the pool, so this range takes the pool's own path.
	if _, err := f.admin.EditFile(path, []string{"198.18.0.0/16"}, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "1.2.3.0/24\n" {
		t.Fatalf("file = %q", data)
	}
	if _, err := f.admin.SwitchExit("pinned", "wg1", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.calls = nil
	if _, err := f.admin.EditFile(path, []string{"198.18.0.0/16"}, nil, "admin"); err == nil || !strings.Contains(err.Error(), "Fake-IP") {
		t.Fatalf("err = %v", err)
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("a refused edit reached the system: %v", f.sys.calls)
	}
}

func TestFamiliesOfOneDomainListStayAGroupWithTheirOwnRanges(t *testing.T) {
	dir := t.TempDir()
	four, six := filepath.Join(dir, "r.ipv4"), filepath.Join(dir, "r.ipv6")
	os.WriteFile(four, []byte("203.0.113.0/24\n198.51.100.0/24\n"), 0o644)
	os.WriteFile(six, []byte("2001:db8::/32\n"), 0o644)
	rules := []map[string]any{
		{"name": "media", "interface": "tap1", "via": "172.31.0.2", "domain_files": []any{"a"}, "ip_range_files": []any{four}},
		{"name": "media6", "interface": "tap1", "via": "fd76::2", "domain_files": []any{"a"}, "ip_range_files": []any{six}},
		{"name": "only4", "interface": "wg1", "via": "10.62.30.1", "ip_range_files": []any{four}},
		{"name": "only6", "interface": "wg1", "via": "fd00::1", "ip_range_files": []any{six}},
	}
	groups := groupedRules(rules)
	if len(groups) != 3 || len(groups[0]) != 2 {
		t.Fatalf("groups = %v", groups)
	}
	group := describeRules(rules, groups[0]...)
	if group.Ranges != 3 || strings.Join(group.Options, ",") != "wg1" {
		t.Fatalf("group = %+v", group)
	}
}

func TestFlushRoutesStopsFlushesAndStartsGate(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.routes)
	state, err := f.admin.FlushRoutes("admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.sys.calls, ","); got != "stop,flush,start,ready" {
		t.Fatalf("calls = %s", got)
	}
	if state.Pending != nil || state.Last == nil || state.Last.Outcome != "flushed" {
		t.Fatalf("state = %+v", state)
	}
	if after, _ := os.ReadFile(f.routes); string(after) != string(before) {
		t.Fatal("a flush changed the configuration")
	}
}

func TestFlushRoutesStartsGateEvenWhenItFails(t *testing.T) {
	for name, set := range map[string]struct {
		fail  func(*fakeAdminSystem)
		calls string
	}{
		"stop":  {func(s *fakeAdminSystem) { s.stopErr = errors.New("no") }, "stop,start,ready"},
		"flush": {func(s *fakeAdminSystem) { s.flushErr = errors.New("no") }, "stop,flush,start,ready"},
		"start": {func(s *fakeAdminSystem) { s.startErr = errors.New("no") }, "stop,flush,start"},
		"ready": {func(s *fakeAdminSystem) { s.readyErr = errors.New("no") }, "stop,flush,start,ready"},
	} {
		f := newAdminFixture(t)
		set.fail(f.sys)
		if _, err := f.admin.FlushRoutes("admin"); err == nil {
			t.Errorf("%s: no error", name)
		}
		if got := strings.Join(f.sys.calls, ","); got != set.calls {
			t.Errorf("%s: calls = %s", name, got)
		}
		state, err := f.admin.State()
		if err != nil || state.Last == nil || state.Last.Outcome != "flush-failed" {
			t.Errorf("%s: state = %+v, %v", name, state, err)
		}
	}
}

func TestFlushRoutesWaitsForAPendingChange(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SwitchExit("textfixture", "tap1", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.calls = nil
	if _, err := f.admin.FlushRoutes("admin"); err == nil {
		t.Fatal("a flush ran over an unconfirmed change")
	}
	if len(f.sys.calls) != 0 {
		t.Fatalf("calls = %v", f.sys.calls)
	}
}

func TestFlushHandler(t *testing.T) {
	f := newAdminFixture(t)
	request := httptest.NewRequest("POST", "/gate/flush", nil)
	recorder := httptest.NewRecorder()
	f.admin.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"outcome":"flushed"`) {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestStateCountsInstalledRoutes(t *testing.T) {
	f := newAdminFixture(t)
	f.sys.routes = []adminRoute{
		{Prefix: "198.18.0.0/15", Via: "172.31.0.2", Interface: "tap1"},
		{Prefix: "1.2.3.0/24", Via: "172.31.0.2", Interface: "tap1"},
		{Prefix: "1.2.3.128/25", Via: "172.31.0.2", Interface: "tap1"},
		{Prefix: "9.9.9.9/32", Via: "10.62.30.1", Interface: "wg1"},
		{Prefix: "2001:db8::1/128", Via: "fd00::1", Interface: "loop10"},
	}
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	stats := state.Routes
	if stats == nil || stats.Total != 5 || stats.Static != 3 || stats.Learned != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(stats.Exits) != 3 || stats.Exits[0] != (AdminExitRoutes{"loop10", 1}) || stats.Exits[1] != (AdminExitRoutes{"tap1", 3}) || stats.Exits[2] != (AdminExitRoutes{"wg1", 1}) {
		t.Fatalf("exits = %+v", stats.Exits)
	}
}

func TestStateWithoutGateStillAnswers(t *testing.T) {
	f := newAdminFixture(t)
	f.sys.routesErr = errors.New("connection refused")
	state, err := f.admin.State()
	if err != nil || state.Routes != nil || len(state.Groups) == 0 {
		t.Fatalf("state = %+v, %v", state, err)
	}
}

func (f *adminFixture) offer(t *testing.T, content string) {
	t.Helper()
	f.admin.opts.ExitsFile = filepath.Join(f.dir, "offered.json")
	if err := os.WriteFile(f.admin.opts.ExitsFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOfferedExitsCanBeChosen(t *testing.T) {
	f := newAdminFixture(t)
	f.offer(t, `[{"interface":"wg100","via":"10.9.0.2"}]`)
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, exit := range state.Exits {
		found = found || exit.Name == "wg100"
	}
	if !found {
		t.Fatalf("not offered: %+v", state.Exits)
	}
	if _, err := f.admin.SwitchExit("textfixture", "wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "textfixture")
	if rule["interface"] != "wg100" || rule["via"] != "10.9.0.2" {
		t.Fatalf("%+v", rule)
	}
}

func TestAnExitOfOneFamilyIsNotOfferedForTheOther(t *testing.T) {
	f := newAdminFixture(t)
	f.offer(t, `[{"interface":"wg100","via":"10.9.0.2"}]`)
	if _, err := f.admin.SwitchExit("mediafixture", "wg100", "admin"); err == nil {
		t.Fatal("a dual-stack rule was sent to an IPv4-only exit")
	}
}

func TestBadOfferedExitsAreIgnored(t *testing.T) {
	f := newAdminFixture(t)
	for _, content := range []string{`not json`, `[{"interface":"wg 1;rm","via":"10.9.0.2"},{"interface":"wg100","via":"nope"}]`} {
		f.offer(t, content)
		state, err := f.admin.State()
		if err != nil {
			t.Fatal(err)
		}
		for _, exit := range state.Exits {
			if exit.Name == "wg100" || strings.Contains(exit.Name, " ") {
				t.Fatalf("%s offered %+v", content, exit)
			}
		}
	}
	f.admin.opts.ExitsFile = filepath.Join(f.dir, "absent.json")
	if _, err := f.admin.State(); err != nil {
		t.Fatal(err)
	}
}

func dnsOf(rule map[string]any) []any {
	value, _ := rule["dns_upstream"].([]any)
	return value
}

func TestParseDNS(t *testing.T) {
	for text, want := range map[string]string{"8.8.8.8": "8.8.8.8", " 8.8.8.8:5353 ": "8.8.8.8:5353", "2001:4860::8888": "2001:4860::8888", "[2001:4860::8888]:5353": "[2001:4860::8888]:5353", "1.1.1.1:53": "1.1.1.1"} {
		value, err := parseDNS(text)
		if err != nil || dnsTextOf(value) != want {
			t.Errorf("%q: %v %v", text, value, err)
		}
	}
	for _, text := range []string{"dns.google", "8.8.8.8:0", "8.8.8.8:99999", "8.8.8.8:x", "fe80::1%eth0"} {
		if value, err := parseDNS(text); err == nil {
			t.Errorf("%q accepted: %v", text, value)
		}
	}
	if value, err := parseDNS("  "); value != nil || err != nil {
		t.Fatalf("empty: %v %v", value, err)
	}
}

func TestSwitchCanSetTheDNS(t *testing.T) {
	f := newAdminFixture(t)
	dns := "9.9.9.9"
	if _, err := f.admin.SwitchRule("vpn", "loop10", nil, "admin"); err == nil {
		t.Fatal("no change was accepted")
	}
	f.offer(t, `[{"interface":"wg100","via":"10.9.0.2"}]`)
	if _, err := f.admin.SwitchRule("textfixture", "wg100", &dns, "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "textfixture")
	if rule["interface"] != "wg100" || dnsTextOf(dnsOf(rule)) != "9.9.9.9" {
		t.Fatalf("%+v", rule)
	}
}

func TestOnlyTheDNSCanChange(t *testing.T) {
	f := newAdminFixture(t)
	dns := "9.9.9.9:5353"
	if _, err := f.admin.SwitchRule("textfixture", "wg1", &dns, "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "textfixture")
	if rule["interface"] != "wg1" || rule["via"] != "10.62.30.1" || dnsTextOf(dnsOf(rule)) != "9.9.9.9:5353" {
		t.Fatalf("%+v", rule)
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.SwitchRule("textfixture", "wg1", &dns, "admin"); err == nil || !strings.Contains(err.Error(), "没有变化") {
		t.Fatalf("an unchanged DNS was applied: %v", err)
	}
	empty := ""
	if _, err := f.admin.SwitchRule("textfixture", "wg1", &empty, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, present := f.rule(t, "textfixture")["dns_upstream"]; present {
		t.Fatal("empty should fall back to the default DNS")
	}
}

func TestFakeIPDNSStaysWithItsExit(t *testing.T) {
	f := newAdminFixture(t)
	empty := ""
	// The default DNS instead of the Fake-IP one: real addresses on the same exit.
	if _, err := f.admin.SwitchRule("mediafixture", "tap1", &empty, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "mediafixture"); rule["fakeip_range"] != nil || rule["dns_upstream"] != nil {
		t.Fatalf("rule: %+v", rule)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if group := f.group(t, "textfixture"); group.OptionDNS["tap1"] != "127.0.0.1:5354" {
		t.Fatalf("the exit's own DNS is not offered: %+v", group)
	}
	if _, err := f.admin.SwitchExit("mediafixture", "loop10", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, present := f.rule(t, "mediafixture")["dns_upstream"]; present {
		t.Fatal("the Fake-IP DNS followed the rule to a real exit")
	}
}

func TestAddRuleWithDNS(t *testing.T) {
	f := newAdminFixture(t)
	dns := "9.9.9.9"
	if _, err := f.admin.AddRuleWithDNS("media", "wg1", nil, f.textfixture, "", &dns, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "media"); dnsTextOf(dnsOf(rule)) != "9.9.9.9" {
		t.Fatalf("%+v", rule)
	}
}

func TestDefaultDNS(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SetDefaultDNS("", "admin"); err == nil {
		t.Fatal("an empty default DNS was accepted")
	}
	state, err := f.admin.SetDefaultDNS("223.5.5.5", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Default.DNS != "223.5.5.5" {
		t.Fatalf("%+v", state.Default)
	}
	entry, _ := readJSONObject(f.opts.Config)
	if upstream, _ := entry["upstream"].([]any); dnsTextOf(upstream) != "223.5.5.5" {
		t.Fatalf("%+v", entry)
	}
	if entry["domain_routes_file"] != f.routes {
		t.Fatal("the rest of the configuration was lost")
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if entry, _ := readJSONObject(f.opts.Config); entry["upstream"] != nil {
		t.Fatalf("not rolled back: %+v", entry)
	}
}

// A configuration as Gate's install.py writes it: a Linux exit whose device Gate generates, so
// it has linux_exit as an object and no interface, and, from older installs, no name.
func TestLinuxExitsAsGateInstallWritesThem(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"wlan0.domains": "a.example\n", "proxy.domains": "", "vpn.domains": "corp.example\n", "media.domains": "b.example\n"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := func(name string) []any { return []any{filepath.Join(dir, name)} }
	entry, _ := json.Marshal(map[string]any{"upstream": []any{"10.61.20.2", 53}, "lan_prefixes": []any{"10.61.30.0/24"}, "routes": []any{
		map[string]any{"owner": "host", "domain_files": path("wlan0.domains"), "linux_exit": map[string]any{"interface": "wlan0", "masquerade": true, "gateway": "10.61.20.1"}},
		map[string]any{"name": "vpn", "interface": "wg0", "via": "10.0.0.1", "domain_files": path("vpn.domains")},
		map[string]any{"name": "proxy", "owner": "host", "domain_files": path("proxy.domains"), "fake_dns": []any{"127.0.0.1", 5354}, "fakeip_range": "198.18.0.0/15", "tproxy_port": 2082},
	}})
	config := filepath.Join(dir, "egress-gate.json")
	if err := os.WriteFile(config, entry, 0o644); err != nil {
		t.Fatal(err)
	}
	admin, err := NewAdmin(AdminOptions{Config: config, StateDir: filepath.Join(dir, "state"), ListDir: dir, Confirm: time.Minute}, &fakeAdminSystem{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if admin.timer != nil {
			admin.timer.Stop()
		}
	})
	state, err := admin.State()
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]AdminGroup{}
	for _, group := range state.Groups {
		groups[group.ID] = group
	}
	if g, ok := groups["wlan0"]; !ok || g.Exit != "wlan0" || len(g.Families) != 1 {
		t.Fatalf("the unnamed Linux exit rule: %+v (groups %v)", g, state.Groups)
	}
	if g := groups["proxy"]; g.Exit != "proxy" || len(g.Families) != 1 || g.Locked != "" {
		t.Fatalf("proxy group: %+v", g)
	}
	if g := groups["vpn"]; !contains(g.Options, "wlan0") {
		t.Fatalf("wlan0 not offered to vpn: %+v", g)
	}

	// Switching to the Linux exit copies how it is reached, and the rule found again by name.
	if _, err := admin.SwitchExit("vpn", "wlan0", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	doc, err := readJSONObject(config)
	if err != nil {
		t.Fatal(err)
	}
	var vpn map[string]any
	for _, item := range doc["routes"].([]any) {
		if rule := item.(map[string]any); rule["name"] == "vpn" {
			vpn = rule
		}
	}
	exit, _ := vpn["linux_exit"].(map[string]any)
	if exit["interface"] != "wlan0" || vpn["interface"] != nil || vpn["via"] != nil {
		t.Fatalf("vpn after the switch: %v", vpn)
	}
	if _, err := admin.AddRule("media", "wlan0", nil, filepath.Join(dir, "media.domains"), "", "admin"); err != nil {
		t.Fatal(err)
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func TestRenameUsedFileWaitsForConfirmation(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.mediafixture)
	target := filepath.Join(f.dir, "streaming.domains")
	state, err := f.admin.RenameFile(f.mediafixture, "streaming.domains", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || strings.Join(f.sys.calls, ",") != "check,sync,restart,ready" {
		t.Fatalf("pending %v, calls %v", state.Pending, f.sys.calls)
	}
	for _, name := range []string{"mediafixture", "mediafixture6"} {
		if got := f.rule(t, name)["domain_files"].([]any)[0]; got != target {
			t.Fatalf("%s points at %v", name, got)
		}
	}
	if _, err := os.Stat(f.mediafixture); err != nil {
		t.Fatal("the old name went before confirmation")
	}
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.mediafixture); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old name still there: %v", err)
	}
	if after, _ := os.ReadFile(target); string(after) != string(before) {
		t.Fatalf("content = %q", after)
	}
}

func TestRenameUsedFileRollsBack(t *testing.T) {
	f := newAdminFixture(t)
	before, _ := os.ReadFile(f.mediafixture)
	target := filepath.Join(f.dir, "streaming.domains")
	if _, err := f.admin.RenameFile(f.mediafixture, "streaming.domains", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.rule(t, "mediafixture")["domain_files"].([]any)[0]; got != f.mediafixture {
		t.Fatalf("rule points at %v", got)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new name left behind: %v", err)
	}
	if after, _ := os.ReadFile(f.mediafixture); string(after) != string(before) {
		t.Fatalf("old content = %q", after)
	}
}

func TestRenameRemovalSurvivesAdminRestart(t *testing.T) {
	f := newAdminFixture(t)
	// On the real clock, so the deadline is still ahead for the restarted service.
	*f.now = time.Now()
	if _, err := f.admin.RenameFile(f.textfixture, "papers.domains", "admin"); err != nil {
		t.Fatal(err)
	}
	f.admin.timer.Stop()
	again, err := NewAdmin(f.opts, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	if again.pending == nil || strings.Join(again.pending.Remove, ",") != f.textfixture {
		t.Fatalf("pending after restart = %+v", again.pending)
	}
	t.Cleanup(func() {
		if again.timer != nil {
			again.timer.Stop()
		}
	})
	if err := again.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.textfixture); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old name still there: %v", err)
	}
}

func TestRenameKeepsASingleReferenceAString(t *testing.T) {
	f := newAdminFixture(t)
	doc, _ := readJSONObject(f.routes)
	for _, item := range doc["routes"].([]any) {
		if rule := item.(map[string]any); rule["name"] == "textfixture" {
			rule["domain_files"] = f.textfixture
		}
	}
	data, _ := json.Marshal(doc)
	os.WriteFile(f.routes, data, 0o640)
	if _, err := f.admin.RenameFile(f.textfixture, "papers.domains", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.rule(t, "textfixture")["domain_files"]; got != filepath.Join(f.dir, "papers.domains") {
		t.Fatalf("domain_files = %#v", got)
	}
}

func TestRenameUnusedFileAndRefusals(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.UploadFile("idle.domains", "a.example\n", false, "admin")
	idle := filepath.Join(f.dir, "idle.domains")
	for _, c := range []struct{ path, name, want string }{
		{idle, "idle.ranges", "must look like"},
		{idle, "../x.domains", "must look like"},
		{idle, "idle.domains", "unchanged"},
		{idle, "textfixture.domains", "already exists"},
		{"/etc/passwd", "x.domains", "not a managed"},
	} {
		if _, err := f.admin.RenameFile(c.path, c.name, "admin"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s -> %s: err = %v", c.path, c.name, err)
		}
	}
	state, err := f.admin.RenameFile(idle, "quiet.domains", "admin")
	if err != nil || state.Pending != nil || len(f.sys.calls) != 0 {
		t.Fatalf("%v, pending %v, calls %v", err, state, f.sys.calls)
	}
	if data, _ := os.ReadFile(filepath.Join(f.dir, "quiet.domains")); string(data) != "a.example\n" {
		t.Fatalf("renamed file = %q", data)
	}
	f.admin.SwitchExit("textfixture", "tap1", "admin")
	if _, err := f.admin.RenameFile(filepath.Join(f.dir, "quiet.domains"), "loud.domains", "admin"); err == nil {
		t.Fatal("a rename went through while a change was pending")
	}
}
