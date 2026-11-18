package ingester

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// End-to-end service regression: only the independent Ingester owns ClickHouse
// writes. It accepts existing JSONL files, persists a checkpoint and metrics,
// then shuts down without requiring a Web process.
func TestIndependentServicePersistsEventsAlertsAndMetrics(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	alerts := filepath.Join(dir, "alerts.jsonl")
	if err := os.WriteFile(events, []byte(sampleLine("id-event")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alerts, []byte(`{"alert_id":"id-alert","rule_id":"R007","severity":"critical","timestamp":"2026-11-18T10:00:00Z"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	counts := map[string]int{}
	db := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := r.URL.Query().Get("query")
		mu.Lock()
		defer mu.Unlock()
		for _, s := range []string{"INSERT INTO runtime_security.events", "INSERT INTO runtime_security.alerts", "INSERT INTO runtime_security.detector_metrics"} {
			if strings.HasPrefix(sql, s) {
				var m map[string]any
				if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				counts[s]++
			}
		}
		w.WriteHeader(200)
	}))
	defer db.Close()
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("redo_events_received_total 14\n")) }))
	defer metrics.Close()
	opts := Defaults()
	opts.ClickHouse = db.URL
	opts.User = "test"
	opts.Events = events
	opts.Alerts = alerts
	opts.Offsets = filepath.Join(dir, "web-offsets.json")
	opts.LockFile = filepath.Join(dir, "instance.lock")
	opts.MetricsURL = metrics.URL + "/metrics"
	opts.Interval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, opts) }()
	deadline := time.After(4 * time.Second)
	for {
		mu.Lock()
		ok := counts["INSERT INTO runtime_security.events"] > 0 && counts["INSERT INTO runtime_security.alerts"] > 0 && counts["INSERT INTO runtime_security.detector_metrics"] > 0
		mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("ingester did not persist all three streams")
		case <-time.After(30 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ingester failed to stop")
	}
	cp, err := loadCheckpoint(opts.Offsets)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{events, alerts} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if cp.Files[p].Offset != st.Size() {
			t.Fatalf("checkpoint for %s: %d != %d", p, cp.Files[p].Offset, st.Size())
		}
	}
}
func TestExclusiveIngesterLockAndInvalidCheckpoint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "instance.lock")
	f, err := acquireInstanceLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if g, err := acquireInstanceLock(p); err == nil {
		g.Close()
		t.Fatal("second writer permitted")
	}
	o := Defaults()
	o.LockFile = filepath.Join(dir, "another.lock")
	o.Offsets = filepath.Join(dir, "bad.json")
	o.MetricsURL = ""
	os.WriteFile(o.Offsets, []byte("not JSON"), 0600)
	if err := Serve(context.Background(), o); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}
