package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTetraUsesExplicitPodAndContextForIndependentSource(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fakekubectl")
	argsFile := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nprintf '%s\\n' '{\"time\":\"2026-11-18T10:00:00Z\"}'\nsleep 1\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := 0
	err := StreamTetra(ctx, TetraConfig{Kubectl: binary, Context: "lab", Namespace: "kube-system", Pod: "tetragon-node-a", Container: "tetragon", FilterNamespace: "security-lab", MinBackoff: time.Millisecond, MaxBackoff: time.Second}, func([]byte) error { got++; cancel(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("expected one event, got %d", got)
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := string(b)
	for _, v := range []string{"--context\nlab\n", "-n\nkube-system\n", "exec\npod/tetragon-node-a\n", "-c\ntetragon\n", "--\ntetra\ngetevents\n-o\njson\n", "--namespace\nsecurity-lab\n"} {
		if !strings.Contains(args, v) {
			t.Fatalf("missing %q in kubectl args %s", v, args)
		}
	}
}
