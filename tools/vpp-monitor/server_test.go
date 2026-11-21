package main

import (
	"io/fs"
	"regexp"
	"testing"
)

func TestDashboardIDsUnique(t *testing.T) {
	document, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, match := range regexp.MustCompile(`\bid="([^"]+)"`).FindAllSubmatch(document, -1) {
		id := string(match[1])
		if seen[id] {
			t.Errorf("duplicate dashboard ID %q: element lookup can select the wrong control", id)
		}
		seen[id] = true
	}
}

// Every element a page script looks up by a literal ID is in the page.
func TestScriptIDsExist(t *testing.T) {
	document, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, match := range regexp.MustCompile(`\bid="([^"]+)"`).FindAllSubmatch(document, -1) {
		ids[string(match[1])] = true
	}
	scripts, err := fs.Glob(webFiles, "web/pages/*.js")
	if err != nil || len(scripts) == 0 {
		t.Fatalf("scripts %v %v", scripts, err)
	}
	for _, name := range append(scripts, "web/app.js") {
		source, err := webFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range regexp.MustCompile(`\$\('([A-Za-z0-9_-]+)'\)`).FindAllSubmatch(source, -1) {
			if !ids[string(match[1])] {
				t.Errorf("%s looks up #%s, which index.html does not have", name, match[1])
			}
		}
	}
}
