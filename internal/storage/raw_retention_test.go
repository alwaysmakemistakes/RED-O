package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRawRetentionQuotaDoesNotStopDetector(t *testing.T) {
	p := filepath.Join(t.TempDir(), "raw.jsonl")
	w, err := OpenRaw(p, 16, 2, 24*time.Hour, 48)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Eight writes force repeated rotations despite a two-segment limit.
	for i := 0; i < 8; i++ {
		if _, err := w.Write([]byte(strings.Repeat(string(rune('a'+i)), 12) + "\n")); err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
	}
	segs, err := Segments(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("expected 2 retained raw segments, got %d", len(segs))
	}
	var bytes int64
	for _, seg := range segs {
		st, _ := os.Stat(seg)
		bytes += st.Size()
	}
	st, _ := os.Stat(p)
	bytes += st.Size()
	if bytes > 48 {
		t.Fatalf("raw budget exceeded: %d", bytes)
	}
	last, _ := os.ReadFile(p)
	if !strings.Contains(string(last), "hhhh") {
		t.Fatalf("active latest telemetry lost: %q", last)
	}
}

func TestRawRetentionPrunesExpiredOnOpen(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "raw.jsonl")
	old := p + ".segment-0000000000000000001-000001"
	if err := os.WriteFile(old, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	w, err := OpenRaw(p, 32, 32, time.Hour, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired raw segment not deleted: %v", err)
	}
}

func TestRawRetentionNeverDeletesEventArchive(t *testing.T) {
	d := t.TempDir()
	raw := filepath.Join(d, "raw.jsonl")
	events := filepath.Join(d, "events.jsonl.segment-0001")
	os.WriteFile(events, []byte("valuable\n"), 0600)
	w, err := OpenRaw(raw, 10, 1, time.Hour, 30)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := w.Write([]byte("1234567\n")); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	b, err := os.ReadFile(events)
	if err != nil || string(b) != "valuable\n" {
		t.Fatalf("event archive touched: %q %v", b, err)
	}
}

func TestRegularLogStillFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	w, err := Open(p, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("11111111\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("22222222\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("33333333\n")); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("expected fail-closed, got %v", err)
	}
}

func TestRawRetentionRejectsInvalidBudget(t *testing.T) {
	if _, err := OpenRaw(filepath.Join(t.TempDir(), "raw"), 64, 2, time.Hour, 32); err == nil {
		t.Fatal("segment larger than total budget should fail")
	}
}
