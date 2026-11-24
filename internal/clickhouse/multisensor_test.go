package clickhouse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInitAddsOriginColumnsWithoutReplacingTables(t *testing.T) {
	queries := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("query"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := New(srv.URL, "default", "pw").Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(queries, "\n")
	for _, fragment := range []string{
		"ALTER TABLE runtime_security.events ADD COLUMN IF NOT EXISTS sensor_id",
		"ALTER TABLE runtime_security.events ADD COLUMN IF NOT EXISTS cluster",
		"ALTER TABLE runtime_security.events ADD COLUMN IF NOT EXISTS received_at",
		"ALTER TABLE runtime_security.alerts ADD COLUMN IF NOT EXISTS sensor_ids",
		"ALTER TABLE runtime_security.alerts ADD COLUMN IF NOT EXISTS cluster",
	} {
		if !strings.Contains(all, fragment) {
			t.Fatalf("missing schema migration: %s", fragment)
		}
	}
}
