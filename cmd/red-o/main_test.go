package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIUsageAndInvalid(t *testing.T) {
	if got := run([]string{"help"}); got != 0 {
		t.Fatalf("help status=%d", got)
	}
	if got := run([]string{"bogus", "start"}); got != 2 {
		t.Fatalf("bogus status=%d", got)
	}
	if got := run([]string{"web"}); got != 2 {
		t.Fatalf("invalid syntax status=%d", got)
	}
}
func TestProjectRootFromRepository(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := findProjectRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "configs", "rules.json")); err != nil {
		t.Fatal(err)
	}
	if dir == root {
		t.Fatal("test expected to run inside cmd/red-o")
	}
}
