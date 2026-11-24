package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseVersionContract(t *testing.T) {
	root, err := findProjectRoot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(v)); got != releaseVersion {
		t.Fatalf("VERSION=%q != CLI version=%q", got, releaseVersion)
	}
	b, err := os.ReadFile(filepath.Join(root, "RELEASE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != releaseVersion {
		t.Fatalf("RELEASE.json=%q != %q", meta.Version, releaseVersion)
	}
	if currentRelease().Version != releaseVersion {
		t.Fatal("version not reported correctly")
	}
}

func TestVersionArguments(t *testing.T) {
	if got := run([]string{"version"}); got != 0 {
		t.Fatalf("version exit=%d", got)
	}
	if got := run([]string{"version", "-json"}); got != 0 {
		t.Fatalf("version -json exit=%d", got)
	}
	if got := run([]string{"version", "--bad-option"}); got != 2 {
		t.Fatalf("unexpected exit=%d", got)
	}
}
