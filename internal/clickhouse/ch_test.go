package clickhouse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInsertAndQuery(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		u, p, _ := r.BasicAuth()
		if u != "tester" || p != "secret" {
			t.Errorf("credentials missing")
		}
		if !strings.Contains(r.URL.Query().Get("query"), "runtime_security.events") {
			t.Errorf("wrong query")
		}
		if strings.Contains(r.URL.Query().Get("query"), "INSERT") {
			w.WriteHeader(200)
			return
		}
		w.Write([]byte("{\"payload\":\"{\\\"event_id\\\":\\\"x\\\"}\"}\n"))
	}))
	defer srv.Close()
	c := New(srv.URL, "tester", "secret")
	if err := c.Insert(context.Background(), "events", []map[string]any{{"event_id": "x"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(context.Background(), "SELECT payload FROM runtime_security.events FORMAT JSONEachRow", nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
