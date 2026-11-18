package webapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime-detector/internal/clickhouse"
	"strings"
	"testing"
)

func TestMetricsParser(t *testing.T) {
	vals, err := parseMetrics(strings.NewReader("# TYPE redo_events_received_total counter\nredo_events_received_total 13\nredo_events_normalized_total 11\nredo_processing_duration_seconds_count 9\nunknown_secret_metric 900\n"))
	if err != nil || vals["redo_events_received_total"] != 13 || vals["redo_processing_duration_seconds_count"] != 9 {
		t.Fatalf("metrics: %v %v", vals, err)
	}
	if _, ok := vals["unknown_secret_metric"]; ok {
		t.Fatal("unknown metric leaked")
	}
}
func TestMetricsMonitorAndFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("redo_events_received_total 3\nredo_events_normalized_total 2\n"))
	}))
	defer srv.Close()
	m, err := newMetricsMonitor(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	m.sample(context.Background())
	if len(m.history) != 1 || m.lastError != "" {
		t.Fatalf("unexpected monitor state %+v", m)
	}
	response := httptest.NewRecorder()
	m.serve(response, httptest.NewRequest("GET", "/api/metrics", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"available":true`) {
		t.Fatal(response.Body.String())
	}
	srv.Close()
	m.sample(context.Background())
	response = httptest.NewRecorder()
	m.serve(response, httptest.NewRequest("GET", "/api/metrics", nil))
	if !strings.Contains(response.Body.String(), `"available":false`) {
		t.Fatal("unavailable backend must be shown")
	}
}
func TestMetricsRejectRemote(t *testing.T) {
	for _, s := range []string{"http://example.org:9095/metrics", "https://127.0.0.1:9095/metrics", "http://127.0.0.1:9095/other"} {
		if _, e := newMetricsMonitor(s); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

// The Web API must return persisted snapshots after the original monitor process is gone.
func TestMetricsHistoryFromClickHouse(t *testing.T) {
	dbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := r.URL.Query().Get("query")
		if strings.Contains(sql, "detector_metrics") && strings.HasPrefix(sql, "SELECT") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"at":"2026-11-10T10:00:00","payload":"{\"redo_events_received_total\":7}"}` + "\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer dbServer.Close()
	m := &metricsMonitor{db: clickhouse.New(dbServer.URL, "default", "pass"), instance: "detector-local", lastError: "offline"}
	rec := httptest.NewRecorder()
	m.serve(rec, httptest.NewRequest("GET", "/api/metrics?window=24h", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"redo_events_received_total":7`) {
		t.Fatalf("history unavailable: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatal("offline must remain offline with stored data")
	}
	rec = httptest.NewRecorder()
	m.serve(rec, httptest.NewRequest("GET", "/api/metrics?window=bad", nil))
	if rec.Code != 400 {
		t.Fatalf("unsafe window accepted: %d", rec.Code)
	}
}
