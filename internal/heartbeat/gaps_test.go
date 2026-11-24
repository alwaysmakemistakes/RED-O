package heartbeat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveredGapAndJournal(t *testing.T) {
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	now := base
	r := New(filepath.Join(t.TempDir(), "heartbeat.json"), "tetra")
	r.clock = func() time.Time { return now }
	if got := r.Connected(); got != nil {
		t.Fatalf("unexpected initial gap: %+v", got)
	}
	now = now.Add(3 * time.Second)
	r.Disconnected(errors.New("test link failure"))
	r.Disconnected(errors.New("repeated failed retry"))
	s := r.Snapshot()
	if s.Disconnections != 1 || s.CurrentGapStartedAt == nil || s.Connected {
		t.Fatalf("open gap incorrect: %+v", s)
	}
	now = now.Add(2750 * time.Millisecond)
	gap := r.Connected()
	if gap == nil || gap.DurationMilliseconds != 2750 {
		t.Fatalf("gap: %+v", gap)
	}
	s = r.Snapshot()
	if !s.Connected || s.Reconnects != 1 || s.CompletedGaps != 1 || s.TotalGapMilliseconds != 2750 || s.CurrentGapStartedAt != nil {
		t.Fatalf("recovered: %+v", s)
	}
	path := filepath.Join(t.TempDir(), "gaps.jsonl")
	if err := AppendGap(path, *gap); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `"duration_ms":2750`) {
		t.Fatalf("journal: %q %v", b, err)
	}
	if err := r.Write(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(r.path)
	if err != nil || loaded.CompletedGaps != 1 {
		t.Fatalf("read: %+v %v", loaded, err)
	}
}

func TestInitialFailedConnectAndIntentionalStop(t *testing.T) {
	r := New("", "tetra")
	r.Disconnected(errors.New("kubectl unavailable"))
	if g := r.Connected(); g == nil {
		t.Fatal("startup outage must be recorded")
	}
	if r.Snapshot().Reconnects != 1 {
		t.Fatal("recovery should be counted")
	}
	r.Stop()
	if r.Snapshot().CurrentGapStartedAt != nil || r.Snapshot().Connected {
		t.Fatal("intentional stop should not create gap")
	}
}
