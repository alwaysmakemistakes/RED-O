package webapp

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalWebEventsAlertsAndDetail(t *testing.T) {
	d := t.TempDir()
	events := filepath.Join(d, "events.jsonl")
	alerts := filepath.Join(d, "alerts.jsonl")
	data := `{"event_id":"e1","event_type":"process.exec","timestamp":"2026-01-01T00:00:01Z","node":"a","kubernetes":{"namespace":"security-lab","pod":"mypod"},"process":{"binary":"/bin/sh"}}` + "\n" + `{"event_id":"e2","event_type":"network.connect","timestamp":"2026-01-01T00:00:02Z","node":"a","kubernetes":{"namespace":"other","pod":"x"}}` + "\n"
	if err := os.WriteFile(events, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alerts, []byte(`{"alert_id":"a1","rule_id":"R001","severity":"medium","timestamp":"2026-01-01T00:00:01Z","kubernetes":{"namespace":"security-lab"},"related_event_ids":["e1"]}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/events?namespace=security-lab", nil)
	w := httptest.NewRecorder()
	localList(w, req, events, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "e1") || strings.Contains(w.Body.String(), "e2") {
		t.Fatalf("events: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest("GET", "/api/alerts?rule=R001", nil)
	w = httptest.NewRecorder()
	localList(w, req, alerts, true)
	var listed []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 1 {
		t.Fatalf("alerts: %s %v", w.Body.String(), err)
	}
	req = httptest.NewRequest("GET", "/api/alerts/a1", nil)
	w = httptest.NewRecorder()
	localDetail(w, req, alerts, events)
	var result struct {
		Alert  map[string]any   `json:"alert"`
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Events) != 1 || result.Events[0]["event_id"] != "e1" {
		t.Fatalf("detail: %s %v", w.Body.String(), err)
	}
	req = httptest.NewRequest("GET", "/api/agents", nil)
	w = httptest.NewRecorder()
	localAgents(w, req, events)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "observed_recent_jsonl") {
		t.Fatalf("agents: %s", w.Body.String())
	}
}
func TestLocalWebMissingFilesEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()
	localList(w, req, filepath.Join(t.TempDir(), "absent"), false)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("missing JSONL: %s", w.Body.String())
	}
}
