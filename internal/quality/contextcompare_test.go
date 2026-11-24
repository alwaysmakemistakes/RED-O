package quality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"testing"
)

func TestContextComparisonPreservesBaselineAndOriginalInputs(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "events.jsonl")
	alertPath := filepath.Join(dir, "alerts.jsonl")
	mPath := filepath.Join(dir, "manifest.json")
	policyPath := filepath.Join(dir, "policy.json")
	e1 := model.SecurityEvent{EventID: "action-pos", EventType: "k8s.audit", Timestamp: "2026-11-21T12:00:00Z", Sensor: &model.Sensor{Cluster: "lab-k3s"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "bad"}, Audit: &model.Audit{User: "system:admin", Verb: "create", Resource: "pods", Name: "bad"}}
	e2 := model.SecurityEvent{EventID: "action-ok", EventType: "k8s.audit", Timestamp: "2026-11-21T12:01:00Z", Sensor: &model.Sensor{Cluster: "lab-k3s"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "good"}, Audit: &model.Audit{User: "system:admin", Verb: "create", Resource: "pods", Name: "good"}}
	writeJSONL(t, evPath, e1, e2)
	writeJSONL(t, alertPath, model.SecurityAlert{AlertID: "a-pos", RuleID: "R016", Severity: "medium", RelatedEventIDs: []string{"action-pos"}}, model.SecurityAlert{AlertID: "a-ok", RuleID: "R016", Severity: "medium", RelatedEventIDs: []string{"action-ok"}})
	m := Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "W001", Scenario: "workload", Label: "positive", EventIDs: []string{"action-pos"}}, {ID: "W002", Scenario: "workload", Label: "negative", EventIDs: []string{"action-ok"}}}}
	mb, _ := json.Marshal(m)
	if err := os.WriteFile(mPath, mb, 0600); err != nil {
		t.Fatal(err)
	}
	pb := []byte(`{"schema_version":"1.0","policies":[{"id":"approved-change","enabled":true,"decision":"approved","reason":"independent preapproved change","rule_ids":["R016"],"match":{"cluster":"lab-k3s","namespace":"security-lab","audit_user":"system:admin","audit_name":"good"}}]}`)
	if err := os.WriteFile(policyPath, pb, 0600); err != nil {
		t.Fatal(err)
	}
	origEvents, _ := os.ReadFile(evPath)
	origAlerts, _ := os.ReadFile(alertPath)
	live := LiveOptions{Suite: opts().Suite, Rules: opts().Rules, Correlations: opts().Correlations, Manifest: mPath, Events: evPath, Alerts: alertPath, StrictAttribution: true}
	outputDir := filepath.Join(dir, "comparison")
	res, err := CompareLive(CompareOptions{Live: live, ContextPolicy: policyPath, Output: outputDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Baseline.TP != 1 || res.Baseline.FP != 1 || res.Contextual.TP != 1 || res.Contextual.FP != 0 || res.Contextual.TN != 1 || res.Approved != 1 || res.Decisions != 2 {
		t.Fatalf("unexpected baseline/context result %+v", res)
	}
	afterEvents, _ := os.ReadFile(evPath)
	afterAlerts, _ := os.ReadFile(alertPath)
	if string(origEvents) != string(afterEvents) || string(origAlerts) != string(afterAlerts) {
		t.Fatal("modified immutable events/alerts")
	}
	for _, name := range []string{"comparison.json", "comparison-trials.csv", "triage-decisions.jsonl", "baseline/quality.json", "contextual/quality.json"} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// A disabled policy cannot alter the queue.
	pb = []byte(`{"schema_version":"1.0","policies":[]}`)
	if err := os.WriteFile(policyPath, pb, 0600); err != nil {
		t.Fatal(err)
	}
	res, err = CompareLive(CompareOptions{Live: live, ContextPolicy: policyPath, Output: filepath.Join(dir, "no-policy")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Contextual.Counts != res.Baseline.Counts || res.Approved != 0 {
		t.Fatalf("empty policy altered results %+v", res)
	}
}
func TestContextComparisonRefusesMixedEvidence(t *testing.T) {
	d := t.TempDir()
	events := filepath.Join(d, "events.jsonl")
	alerts := filepath.Join(d, "alerts.jsonl")
	manifest := filepath.Join(d, "manifest.json")
	policy := filepath.Join(d, "policy.json")
	writeJSONL(t, events, model.SecurityEvent{EventID: "x"}, model.SecurityEvent{EventID: "outside"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "mixed", RuleID: "R007", RelatedEventIDs: []string{"x", "outside"}})
	mb, _ := json.Marshal(Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "K004", Scenario: "credentials", Label: "positive", EventIDs: []string{"x"}}}})
	os.WriteFile(manifest, mb, 0600)
	os.WriteFile(policy, []byte(`{"schema_version":"1.0","policies":[]}`), 0600)
	_, err := CompareLive(CompareOptions{Live: LiveOptions{Suite: opts().Suite, Rules: opts().Rules, Correlations: opts().Correlations, Manifest: manifest, Events: events, Alerts: alerts, StrictAttribution: true}, ContextPolicy: policy, Output: filepath.Join(d, "out")})
	if err == nil {
		t.Fatal("accepted mixed correlation evidence")
	}
}
