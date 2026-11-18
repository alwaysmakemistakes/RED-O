package ingester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime-detector/internal/clickhouse"
	"runtime-detector/internal/storage"
	"strings"
	"sync"
	"testing"
)

func sampleLine(id string) string {
	return fmt.Sprintf(`{"event_id":%q,"event_type":"process.exec","timestamp":"2026-11-10T10:00:00Z","process":{"binary":"/bin/sh","pid":1,"uid":0}}`+"\n", id)
}
func TestCheckpointResumePartialLineAndRotation(t *testing.T) {
	var mu sync.Mutex
	ids := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), "INSERT INTO runtime_security.events") {
			w.WriteHeader(500)
			return
		}
		defer r.Body.Close()
		var row map[string]any
		dec := json.NewDecoder(r.Body)
		mu.Lock()
		defer mu.Unlock()
		for dec.Decode(&row) == nil {
			ids = append(ids, row["event_id"].(string))
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	check := filepath.Join(dir, "offsets.json")
	db := clickhouse.New(srv.URL, "default", "pass")
	writer, err := storage.Open(path, 320, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte(sampleLine("a"))); err != nil {
		t.Fatal(err)
	}
	cp, _ := loadCheckpoint(check)
	if err = ingestStream(context.Background(), db, "events", path, cp, check); err != nil {
		t.Fatal(err)
	}
	// v0.8.2 must not import incomplete records or consume their bytes.
	if _, err = writer.Write([]byte(strings.TrimSuffix(sampleLine("partial"), "\n"))); err != nil {
		t.Fatal(err)
	}
	if err = ingestStream(context.Background(), db, "events", path, cp, check); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("incomplete JSONL record imported: %v", ids)
	}
	if _, err = writer.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if err = ingestStream(context.Background(), db, "events", path, cp, check); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte(sampleLine("b"))); err != nil {
		t.Fatal(err)
	} // causes rotation
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	cp, err = loadCheckpoint(check)
	if err != nil {
		t.Fatal(err)
	}
	if err = ingestStream(context.Background(), db, "events", path, cp, check); err != nil {
		t.Fatal(err)
	}
	if err = ingestStream(context.Background(), db, "events", path, cp, check); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "a,partial,b" {
		t.Fatalf("unexpected inserts after rotation/restart: %v", ids)
	}
	segs, _ := storage.Segments(path)
	if len(segs) != 0 {
		t.Fatalf("acknowledged segments not cleaned: %v", segs)
	}
}
func TestIngestRetriesAfterInsertFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "failed", 500)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	checkpoint := filepath.Join(dir, "cp.json")
	os.WriteFile(p, []byte(sampleLine("a")), 0600)
	cp, _ := loadCheckpoint(checkpoint)
	db := clickhouse.New(srv.URL, "default", "pass")
	if err := ingestStream(context.Background(), db, "events", p, cp, checkpoint); err == nil {
		t.Fatal("failure should propagate")
	}
	if cp.Files[p].Offset != 0 {
		t.Fatal("advanced cursor after failed insert")
	}
	if err := ingestStream(context.Background(), db, "events", p, cp, checkpoint); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestReplacedFileSameSizeDoesNotSkip(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count++ }))
	defer srv.Close()
	d := t.TempDir()
	path := filepath.Join(d, "events.jsonl")
	cpName := filepath.Join(d, "cp")
	os.WriteFile(path, []byte(sampleLine("a")), 0600)
	cp, _ := loadCheckpoint(cpName)
	db := clickhouse.New(srv.URL, "default", "pass")
	if err := ingestStream(context.Background(), db, "events", path, cp, cpName); err != nil {
		t.Fatal(err)
	}
	repl := path + ".new"
	os.WriteFile(repl, []byte(sampleLine("b")), 0600)
	os.Rename(repl, path)
	if err := ingestStream(context.Background(), db, "events", path, cp, cpName); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("missed replaced same-size file, calls=%d", count)
	}
}
func TestInvalidCheckpointFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cp")
	os.WriteFile(p, []byte("{{not json"), 0600)
	if _, err := loadCheckpoint(p); err == nil {
		t.Fatal("corrupt checkpoint must fail")
	}
}
