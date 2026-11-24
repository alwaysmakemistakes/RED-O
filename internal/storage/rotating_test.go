package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingWriterSegmentsAndQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, err := Open(path, 12, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("two\n")); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("three\n")); err != nil {
		t.Fatal(err)
	} // rotate 8 -> 0
	segs, _ := Segments(path)
	if len(segs) != 1 {
		t.Fatalf("expected one archived segment: %v", segs)
	}
	b, _ := os.ReadFile(segs[0])
	if string(b) != "one\ntwo\n" {
		t.Fatalf("split or missing log entries: %q", b)
	}
	if _, err = w.Write([]byte("four\n")); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("five\n")); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("expected quota error, got %v", err)
	}
	w.Close()
	b, _ = os.ReadFile(path)
	if string(b) != "three\nfour\n" {
		t.Fatalf("unexpected active log: %q", b)
	}
}
func TestWriterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	w, _ := Open(path, 0, 1)
	w.Write([]byte("a\n"))
	w.Close()
	w, _ = Open(path, 0, 1)
	w.Write([]byte("b\n"))
	w.Close()
	b, _ := os.ReadFile(path)
	if string(b) != "a\nb\n" {
		t.Fatalf("lost data on restart: %s", b)
	}
}
