package gate

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeDoc(t *testing.T, doc map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.json")
	writeJSON(t, path, doc)
	return path
}

func TestUnknownFieldsAreNamedWithAHint(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  map[string]any
		want string
	}{
		{"top level spelling", map[string]any{"upstrem": 1}, `unknown field "upstrem"; did you mean "upstream"?`},
		{"rule spelling", map[string]any{"routes": []any{map[string]any{"name": "wg1", "domain_file": 1}}}, `rule wg1: unknown field "domain_file"; did you mean "domain_files"?`},
		{"unnamed rule", map[string]any{"routes": []any{map[string]any{}, map[string]any{"domain": 1}}}, `rule 2: unknown field "domain"; did you mean "domains"?`},
		{"exit spelling", map[string]any{"routes": []any{map[string]any{"name": "wg1", "linux_exit": map[string]any{"masqurade": true}}}}, `rule wg1 linux_exit: unknown field "masqurade"; did you mean "masquerade"?`},
		{"rule field at the top", map[string]any{"domains": 1}, `unknown field "domains"; it belongs in a rule`},
		{"exit field in a rule", map[string]any{"routes": []any{map[string]any{"name": "wg1", "gateway": 1}}}, `unknown field "gateway"; it belongs in linux_exit`},
		{"top field in a rule", map[string]any{"routes": []any{map[string]any{"name": "wg1", "vpp_socket": 1}}}, `unknown field "vpp_socket"; it belongs in the top level`},
		{"rule field in an exit", map[string]any{"routes": []any{map[string]any{"name": "wg1", "linux_exit": map[string]any{"domains": 1}}}}, `unknown field "domains"; it belongs in the rule, outside linux_exit`},
		{"nothing close", map[string]any{"sync_program": 1}, `unknown field "sync_program"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems := unknownFields(tc.doc, "f.json")
			if len(problems) != 1 || !strings.HasSuffix(problems[0], tc.want) {
				t.Fatalf("got %q", problems)
			}
		})
	}
}

func TestEveryUnknownFieldIsReportedAtOnce(t *testing.T) {
	path := writeDoc(t, map[string]any{"b": 1, "a": 1, "routes": []any{map[string]any{"c": 1}}})
	err := refuseUnknownFields(path)
	if err == nil {
		t.Fatal("accepted")
	}
	for _, name := range []string{`"a"`, `"b"`, `"c"`} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("%s missing from %v", name, err)
		}
	}
}

func TestLinkedFilesAreChecked(t *testing.T) {
	runtime := writeDoc(t, map[string]any{"vpp_sockt": "/x"})
	routes := writeDoc(t, map[string]any{"routes": []any{map[string]any{"nam": "x"}}})
	entry := writeDoc(t, map[string]any{"route_config": runtime, "domain_routes_file": routes})
	err := refuseUnknownFields(entry)
	if err == nil || !strings.Contains(err.Error(), "vpp_sockt") || !strings.Contains(err.Error(), `"nam"`) {
		t.Fatalf("got %v", err)
	}
}

func TestEveryFieldTheLoadersReadIsKnown(t *testing.T) {
	// Keys read through a helper or a loop are easy to miss, and refusing one breaks a working configuration.
	sources := map[string]map[string]bool{}
	for _, file := range []string{"config.go", "devices.go"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = map[string]bool{}
		for _, match := range regexp.MustCompile(`(?:doc|obj|route|entry|runtime|routesDoc)\["([a-z_0-9]+)"\]`).FindAllStringSubmatch(string(data), -1) {
			sources[file][match[1]] = true
		}
		for _, match := range regexp.MustCompile(`listFiles\(\w+, "([a-z_0-9]+)"\)`).FindAllStringSubmatch(string(data), -1) {
			sources[file][match[1]] = true
		}
		for _, match := range regexp.MustCompile(`\[\]string\{("[a-z_0-9]+"(?:, "[a-z_0-9]+")*)\} \{`).FindAllStringSubmatch(string(data), -1) {
			for _, name := range regexp.MustCompile(`"([a-z_0-9]+)"`).FindAllStringSubmatch(match[1], -1) {
				if strings.Contains(name[1], "dns") {
					sources[file][name[1]] = true
				}
			}
		}
	}
	for file, names := range sources {
		for name := range names {
			if !knownFields[name] && !knownRouteFields[name] {
				t.Errorf("%s reads %q, which the configuration check would refuse", file, name)
			}
		}
	}
}

func TestDocumentationAndExamplesUseOnlyKnownFields(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```json\n(.*?)```").FindAllSubmatch(readme, -1)
	if len(blocks) == 0 {
		t.Fatal("no examples found")
	}
	for _, block := range blocks {
		var doc map[string]any
		if err := json.Unmarshal(block[1], &doc); err != nil {
			t.Fatalf("%v in:\n%s", err, block[1])
		}
		// Some examples show one rule rather than a whole file.
		_, whole := doc["routes"]
		_, rule := doc["domain_files"]
		if _, domains := doc["domains"]; !whole && (rule || domains) {
			doc = map[string]any{"routes": []any{doc}}
		}
		if problems := unknownFields(doc, "README.md"); len(problems) > 0 {
			t.Errorf("%q in:\n%s", problems, block[1])
		}
	}
	paths, _ := filepath.Glob("example/*.json")
	if len(paths) == 0 {
		t.Fatal("no example files found")
	}
	for _, path := range paths {
		if err := refuseUnknownFields(path); err != nil {
			t.Error(err)
		}
	}
	for _, match := range regexp.MustCompile("(?m)^\\| `([a-z_0-9]+)` \\|").FindAllSubmatch(readme, -1) {
		name := string(match[1])
		if !knownFields[name] && !knownRouteFields[name] && !knownExitFields[name] {
			t.Errorf("the field reference documents %q, which the configuration check would refuse", name)
		}
	}
}

func TestDeviceSyncRefusesAnUnknownField(t *testing.T) {
	useDeviceDirs(t)
	_, calls := fakeLinuxTools(t)
	rule := exitRule("wg1")
	rule["domain_file"] = []any{"x"}
	path := writeDualStackConfig(t, rule)
	err := SyncDevices(path, false)
	if err == nil || !strings.Contains(err.Error(), `did you mean "domain_files"`) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(calls(), "nft") || strings.Contains(calls(), "ip ") {
		t.Fatalf("touched the host:\n%s", calls())
	}
	if err := SyncDevices(path, true); err == nil {
		t.Fatal("a dry run accepted it")
	}
}

func TestGateOnlyWarnsAboutAnUnknownField(t *testing.T) {
	var out strings.Builder
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	warnUnknownFields(writeDoc(t, map[string]any{"sync_program": "/x"}))
	if !strings.Contains(out.String(), `unknown field "sync_program"`) || !strings.Contains(out.String(), "ignored") {
		t.Fatal(out.String())
	}
}
