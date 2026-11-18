package ingester

import (
	"context"
	"encoding/json"
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

// Emulates a ClickHouse outage during JSONL rotation, then Ingester restart and
// recovery of multiple archived segments before the active file.
func TestArchivedSegmentsRecoverAfterClickHouseOutage(t *testing.T) {
	var mu sync.Mutex
	online := false
	received := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !online {
			http.Error(w, "ClickHouse unavailable", http.StatusServiceUnavailable)
			return
		}
		var row map[string]any
		dec := json.NewDecoder(r.Body)
		for dec.Decode(&row) == nil {
			received = append(received, row["event_id"].(string))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	p := filepath.Join(dir, "live-events.jsonl")
	checkpoint := filepath.Join(dir, "web-offsets.json")
	writer, err := storage.Open(p, 200, 20)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"outage-01", "outage-02", "outage-03", "outage-04", "outage-05"}
	for _, id := range expected {
		if _, err := writer.Write([]byte(sampleLine(id))); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	segs, err := storage.Segments(p)
	if err != nil || len(segs) < 2 {
		t.Fatalf("expected rotated segments, got %v %v", segs, err)
	}
	db := clickhouse.New(srv.URL, "", "")
	cp, _ := loadCheckpoint(checkpoint)
	if err := ingestStream(context.Background(), db, "events", p, cp, checkpoint); err == nil {
		t.Fatal("expected outage to fail")
	}
	for _, s := range segs {
		if _, err := os.Stat(s); err != nil {
			t.Fatalf("unacknowledged segment deleted: %v", err)
		}
	}
	if _, err := os.Stat(checkpoint); !os.IsNotExist(err) {
		t.Fatalf("checkpoint should not advance during outage: %v", err)
	}
	// Ingester restarts: a new checkpoint object is loaded from disk.
	cp, err = loadCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	online = true
	mu.Unlock()
	for i := 0; i < 20; i++ {
		if err = ingestStream(context.Background(), db, "events", p, cp, checkpoint); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(received, ",") != strings.Join(expected, ",") {
		t.Fatalf("missing/duplicate/out-of-order ids: %v", received)
	}
	segs, _ = storage.Segments(p)
	if len(segs) != 0 {
		t.Fatalf("committed archives must be removed: %v", segs)
	}
	final, err := loadCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if final.Files[p].Offset != st.Size() {
		t.Fatalf("active file not fully acknowledged: %d != %d", final.Files[p].Offset, st.Size())
	}
}
