package collector

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadJSONStream(t *testing.T) {
	input := "{\n\"time\": \"first\"\n}\n{\"time\":\"second\"}\n"
	got := 0
	err := readJSONStream(context.Background(), strings.NewReader(input), func(b []byte) error {
		got++
		if !strings.Contains(string(b), "time") {
			t.Fatal(string(b))
		}
		return nil
	})
	if err != nil || got != 2 {
		t.Fatalf("got=%d err=%v", got, err)
	}
}
func TestReadJSONStreamHandlerError(t *testing.T) {
	expected := errors.New("output failed")
	err := readJSONStream(context.Background(), strings.NewReader(`{"time":"now"}`), func([]byte) error { return expected })
	if !errors.Is(err, expected) {
		t.Fatal(err)
	}
}
func TestTetraReconnect(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "kubectl")
	// Simulate the gRPC client ending: collector must reconnect.
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '{\"time\":\"x\"}\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	count := 0
	err := StreamTetra(ctx, TetraConfig{Kubectl: script, Namespace: "kube-system", DaemonSet: "tetragon", Container: "tetragon", MinBackoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond}, func(b []byte) error {
		count++
		if count == 3 {
			cancel()
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if count < 3 {
		t.Fatalf("expected retries, got %d", count)
	}
}

// The command's actual output path, not just the decoder helper, must accept
// pretty-printed JSON objects as well as JSONL.
func TestStreamTetraPrettyJSON(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "kubectl")
	content := "#!/bin/sh\nprintf '{\\n  \"time\": \"first\"\\n}\\n{\"time\":\"second\"}\\n'\n"
	if err := os.WriteFile(script, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	count := 0
	err := StreamTetra(ctx, TetraConfig{Kubectl: script, Namespace: "kube-system", DaemonSet: "tetragon", Container: "tetragon", MinBackoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond}, func(b []byte) error {
		if !strings.Contains(string(b), "time") {
			t.Fatalf("unexpected %s", b)
		}
		count++
		if count == 2 {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 JSON objects, got %d", count)
	}
}
