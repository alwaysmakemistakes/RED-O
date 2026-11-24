package webapp

import (
	"encoding/json"
	"path/filepath"
	"runtime-detector/internal/heartbeat"
	"testing"
	"time"
)

func TestCollectorHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat.json")
	if got := collectorHealth(path, "main")["status"]; got != "unknown" {
		t.Fatalf("missing: %v", got)
	}
	r := heartbeat.New(path, "tetra")
	r.Connected()
	if err := r.Write(); err != nil {
		t.Fatal(err)
	}
	// VM hostname need not be main; assert mismatch is explicitly reported.
	s, err := heartbeat.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := collectorHealth(path, s.Node)["status"]; got != "connected" {
		t.Fatalf("connected: %v", got)
	}
	if got := collectorHealth(path, "a-different-node")["status"]; got != "unknown" {
		t.Fatalf("mismatch: %v", got)
	}
	s.UpdatedAt = time.Now().Add(-time.Minute).UTC()
	b, _ := json.Marshal(s)
	if err := heartbeat.WriteAtomic(path, b); err != nil {
		t.Fatal(err)
	}
	if got := collectorHealth(path, s.Node)["status"]; got != "stale" {
		t.Fatalf("stale: %v", got)
	}
}
