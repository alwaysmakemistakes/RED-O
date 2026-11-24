package quality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"strings"
	"testing"
)

func opts() RunOptions {
	return RunOptions{Suite: "../../tests/fixtures/detection-quality/scenarios.json", Rules: "../../configs/rules.json", Correlations: "../../configs/correlations.json", Runs: 1}
}
func TestSyntheticSevenScenariosSnapshot(t *testing.T) {
	report, err := RunSynthetic(opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ByScenario) != 7 || len(report.Trials) != 35 {
		t.Fatalf("coverage scenarios=%d cases=%d", len(report.ByScenario), len(report.Trials))
	}
	// Deliberately includes a missed indicator and a benign mimic for each scenario.
	if report.TP != 14 || report.FP != 7 || report.FN != 7 || report.TN != 7 {
		t.Fatalf("snapshot confusion changed: %+v", report.Counts)
	}
	for _, s := range report.ByScenario {
		if s.TP != 2 || s.FP != 1 || s.FN != 1 || s.TN != 1 {
			t.Fatalf("scenario %s %+v", s.ID, s.Counts)
		}
	}
	if report.F1 < 0.66 || report.F1 > 0.67 {
		t.Fatalf("unexpected F1 %g", report.F1)
	}
	if err = Write(report, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
func TestRepeatedFixturesNotIndependent(t *testing.T) {
	o := opts()
	o.Runs = 2
	r, e := RunSynthetic(o)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Trials) != 70 || r.TP != 28 {
		t.Fatalf("repeat accounting %+v", r.Counts)
	}
	o.Runs = 101
	if _, e = RunSynthetic(o); e == nil {
		t.Fatal("accepted unrealistic repetitions")
	}
}
func writeJSONL(t *testing.T, path string, records ...any) {
	t.Helper()
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range records {
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(append(b, '\n')); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestLiveEventAttributionAndValidation(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	alerts := filepath.Join(dir, "alerts.jsonl")
	manifest := filepath.Join(dir, "groundtruth.json")
	writeJSONL(t, events, model.SecurityEvent{EventID: "good", EventType: "k8s.audit", Timestamp: "2026-11-18T10:00:00Z"}, model.SecurityEvent{EventID: "benign", EventType: "k8s.audit", Timestamp: "2026-11-18T10:00:01Z"}, model.SecurityEvent{EventID: "outside", EventType: "process.exec", Timestamp: "2026-11-18T10:00:02Z"})
	// An unrelated global alert must not be attributed to either trial.
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "a1", RuleID: "R016", RelatedEventIDs: []string{"good"}}, model.SecurityAlert{AlertID: "a2", RuleID: "R001", RelatedEventIDs: []string{"good"}}, model.SecurityAlert{AlertID: "a3", RuleID: "R016", RelatedEventIDs: []string{"outside"}})
	m := Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "t-pos", Scenario: "workload", Label: "positive", EventIDs: []string{"good"}}, {ID: "t-neg", Scenario: "workload", Label: "negative", EventIDs: []string{"benign"}}}}
	save := func() {
		t.Helper()
		b, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(manifest, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	save()
	o := LiveOptions{Suite: opts().Suite, Rules: opts().Rules, Correlations: opts().Correlations, Manifest: manifest, Events: events, Alerts: alerts}
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.TP != 1 || r.TN != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("wrong confusion counts %+v", r.Counts)
	}
	if len(r.Trials[0].OtherObservedRules) != 1 || r.Trials[0].OtherObservedRules[0] != "R001" {
		t.Fatalf("other rule noise not reported %+v", r.Trials[0])
	}
	// Every negative trial is scorable even if alert file is empty.
	if e = os.WriteFile(alerts, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	r, e = EvaluateLive(o)
	if e != nil {
		t.Fatalf("empty alerts must be accepted: %v", e)
	}
	if r.FN != 1 || r.TN != 1 {
		t.Fatalf("empty alerts confusion %+v", r.Counts)
	}
	// Absent evidence must be rejected, never treated as a false negative.
	m.Trials[0].EventIDs = []string{"missing"}
	save()
	_, e = EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "occurs 0 times") {
		t.Fatalf("expected missing evidence error: %v", e)
	}
	m.Trials[0].EventIDs = []string{"benign"}
	save()
	_, e = EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "reused") {
		t.Fatalf("expected duplicate event ownership error: %v", e)
	}
}
func TestLiveRefusesMixedTrialAlert(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	alerts := filepath.Join(dir, "alerts.jsonl")
	manifest := filepath.Join(dir, "manifest.json")
	writeJSONL(t, events, map[string]string{"event_id": "one"}, map[string]string{"event_id": "two"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "shared", RuleID: "R016", RelatedEventIDs: []string{"one", "two"}})
	m := Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "a", Scenario: "workload", Label: "positive", EventIDs: []string{"one"}}, {ID: "b", Scenario: "workload", Label: "negative", EventIDs: []string{"two"}}}}
	b, _ := json.Marshal(m)
	os.WriteFile(manifest, b, 0600)
	o := LiveOptions{Suite: opts().Suite, Rules: opts().Rules, Correlations: opts().Correlations, Manifest: manifest, Events: events, Alerts: alerts}
	_, e := EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "spans different trial") {
		t.Fatalf("expected multi-trial attribution rejection, got %v", e)
	}
}
