package metricsscrape

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAndRejectRemote(t *testing.T) {
	vals, err := Parse(strings.NewReader("# HELP metric\nredo_events_received_total 9\nredo_events_normalized_total 8\nunknown_secret 5\n"))
	if err != nil || vals["redo_events_received_total"] != 9 {
		t.Fatalf("invalid parsing: %v %v", vals, err)
	}
	if _, ok := vals["unknown_secret"]; ok {
		t.Fatal("unknown metric leaked")
	}
	for _, endpoint := range []string{"http://example.org:9095/metrics", "https://127.0.0.1:9095/metrics", "http://127.0.0.1:9095/redirect", "http://user:pwd@127.0.0.1:9095/metrics"} {
		if _, err := New(endpoint); err == nil {
			t.Fatalf("unsafe endpoint: %s", endpoint)
		}
	}
}
func TestScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("redo_events_received_total 21\n")) }))
	defer srv.Close()
	s, err := New(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	vals, err := s.Scrape(context.Background())
	if err != nil || vals["redo_events_received_total"] != 21 {
		t.Fatalf("scraped: %v %v", vals, err)
	}
}
