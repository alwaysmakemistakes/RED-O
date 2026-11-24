package detectorapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"strings"
	"testing"
)

func TestContextEnrichmentDoesNotSuppressRealAlerts(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "rawinput.jsonl")
	if err := os.WriteFile(input, []byte(rawExec("2026-11-21T17:00:00Z")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "context.json")
	data := []byte(`{"schema_version":"1.0","policies":[{"id":"approved","enabled":true,"decision":"approved","reason":"test-only approved pod","rule_ids":["R001"],"match":{"namespace":"security-lab","pod":"ebpf-test"}}]}`)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	old := contextPolicyPath
	contextPolicyPath = p
	defer func() { contextPolicyPath = old }()
	events := filepath.Join(d, "events.jsonl")
	alerts := filepath.Join(d, "alerts.jsonl")
	err := runModeSourceFiltered(context.Background(), "jsonl", "kubectl", "kube-system", "", input, events, filepath.Join(d, "raw.jsonl"), "../../configs/rules.json", "", alerts, "forensic", false, 10)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(alerts)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	found := false
	for _, line := range lines {
		var a model.SecurityAlert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
		if a.RuleID == "R001" {
			if a.Context == nil || a.Context.TriageAction != "approved" || a.Severity != "medium" || a.Context.OriginalSeverity != "medium" || a.Context.PolicyID != "approved" {
				t.Fatalf("bad context %+v", a)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected original R001 alert, got %s", b)
	}
}
