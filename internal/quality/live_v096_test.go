package quality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"strings"
	"testing"
)

func testLiveFiles(t *testing.T) (LiveOptions, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	alerts := filepath.Join(dir, "alerts.jsonl")
	manifest := filepath.Join(dir, "manifest.json")
	o := LiveOptions{Suite: opts().Suite, Rules: opts().Rules, Correlations: opts().Correlations, Manifest: manifest, Events: events, Alerts: alerts, StrictAttribution: true}
	return o, events, alerts, manifest
}
func writeManifest(t *testing.T, path string, m Manifest) {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func action(id, scenario, label string, ids ...string) Trial {
	return Trial{ID: id, Scenario: scenario, Label: label, EventIDs: ids,
		ActionID: "action-" + id, ActionStatus: "completed", ActionStartedAt: "2026-11-21T10:00:00Z", ActionFinishedAt: "2026-11-21T10:00:01Z"}
}
func TestLiveV096TelemetryAndLatency(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	writeJSONL(t, events,
		model.SecurityEvent{EventID: "good", EventType: "k8s.audit", Timestamp: "2026-11-21T10:00:00.5Z"},
		model.SecurityEvent{EventID: "benign", EventType: "k8s.audit", Timestamp: "2026-11-21T10:00:00.5Z"},
	)
	writeJSONL(t, alerts, model.SecurityAlert{
		AlertID: "one-alert", RuleID: "R016", RelatedEventIDs: []string{"good"},
		Timestamp: "2026-11-21T10:00:00.5Z", DetectedAt: "2026-11-21T10:00:01.5Z", EmittedAt: "2026-11-21T10:00:02Z",
	})
	writeManifest(t, manifest, Manifest{SchemaVersion: "1.1", Trials: []Trial{
		action("positive-observed", "workload", "positive", "good"),
		action("negative-observed", "workload", "negative", "benign"),
		action("positive-missing", "workload", "positive"),
		action("negative-missing", "workload", "negative"),
	}})
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.TP != 1 || r.TN != 1 || r.FN != 0 || r.FP != 0 {
		t.Fatalf("observed counts: %+v", r.Counts)
	}
	if r.Coverage.Actions != 4 || r.Coverage.Observed != 2 || r.Coverage.Missing != 2 || r.Coverage.Rate == nil || *r.Coverage.Rate != 0.5 {
		t.Fatalf("coverage: %+v", r.Coverage)
	}
	if r.EndToEnd.TP != 1 || r.EndToEnd.FN != 1 || r.EndToEndRecall == nil || *r.EndToEndRecall != 0.5 {
		t.Fatalf("e2e: %+v %v", r.EndToEnd, r.EndToEndRecall)
	}
	if r.Latency.Samples != 1 || r.Latency.P50Ms == nil || *r.Latency.P50Ms != 2000 {
		t.Fatalf("latency: %+v", r.Latency)
	}
	if r.Trials[0].EventToDetectionMs == nil || *r.Trials[0].EventToDetectionMs != 1000 {
		t.Fatalf("process latency: %+v", r.Trials[0])
	}
	if r.Trials[2].Confusion != "UNOBSERVED" || r.Trials[3].Confusion != "UNOBSERVED" {
		t.Fatalf("missing trials not unobserved: %+v", r.Trials)
	}
	output := t.TempDir()
	if e = Write(r, output); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(output, "quality-latency.csv"))
	if e != nil || !strings.Contains(string(b), "2000.0000") {
		t.Fatalf("missing latency csv: %v %s", e, b)
	}
}
func TestLiveV096StrictMixedExternal(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	writeJSONL(t, events, map[string]string{"event_id": "one"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "mixed", RuleID: "R007", RelatedEventIDs: []string{"one", "outside"}})
	writeManifest(t, manifest, Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "one", Scenario: "credentials", Label: "positive", EventIDs: []string{"one"}}}})
	_, e := EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "mixes trial evidence") {
		t.Fatalf("expected mixed-external rejection, got %v", e)
	}
	o.StrictAttribution = false
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.TP != 1 {
		t.Fatalf("legacy mode did not attribute: %+v", r.Counts)
	}
	if !strings.Contains(strings.Join(r.Caveats, " "), "strict attribution disabled") {
		t.Fatalf("no warning: %+v", r.Caveats)
	}
}
func TestLiveV096RejectForgedActionAndPartial(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	writeJSONL(t, events, map[string]string{"event_id": "one"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "hit", RuleID: "R016", RelatedEventIDs: []string{"one"}})
	m := Manifest{SchemaVersion: "1.1", Trials: []Trial{action("incomplete", "workload", "positive", "one", "absent")}}
	writeManifest(t, manifest, m)
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.Coverage.Partial != 1 || r.TP != 0 || r.EndToEnd.FN != 1 || r.Trials[0].Confusion != "PARTIAL_TELEMETRY" {
		t.Fatalf("partial improperly scored: %+v", r)
	}
	m.Trials[0].ActionID = ""
	writeManifest(t, manifest, m)
	_, e = EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "action_id") {
		t.Fatalf("missing provenance accepted: %v", e)
	}
	m.Trials[0] = action("bad", "workload", "negative", "one")
	m.Trials[0].ActionFinishedAt = "2026-11-21T09:00:00Z"
	writeManifest(t, manifest, m)
	_, e = EvaluateLive(o)
	if e == nil || !strings.Contains(e.Error(), "before start") {
		t.Fatalf("bad clock accepted: %v", e)
	}
}
func TestLiveV096LegacyTimestampNA(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	writeJSONL(t, events, map[string]string{"event_id": "one"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "hit", RuleID: "R016", Timestamp: "2026-11-21T10:00:00Z", RelatedEventIDs: []string{"one"}})
	writeManifest(t, manifest, Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "old", Scenario: "workload", Label: "positive", EventIDs: []string{"one"}}}})
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.TP != 1 || r.Latency.Samples != 0 || r.Trials[0].LatencyMs != nil {
		t.Fatalf("legacy latency should be NA: %+v", r)
	}
}

func TestLiveV096EntirelyUnobserved(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	if e := os.WriteFile(events, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(alerts, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	writeManifest(t, manifest, Manifest{SchemaVersion: "1.1", Trials: []Trial{action("missing-all", "workload", "positive")}})
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.Coverage.Missing != 1 || r.FN != 0 || r.EndToEnd.FN != 1 || r.EndToEndRecall == nil || *r.EndToEndRecall != 0 {
		t.Fatalf("all missing must not be scored as rule FN: %+v", r)
	}
}
func TestServiceAccountTracingPolicyBothPaths(t *testing.T) {
	b, e := os.ReadFile("../../deployments/tracing-policies/serviceaccount-token.yaml")
	if e != nil {
		t.Fatal(e)
	}
	for _, prefix := range []string{"/run/secrets/kubernetes.io/serviceaccount/", "/var/run/secrets/kubernetes.io/serviceaccount/"} {
		if !strings.Contains(string(b), prefix) {
			t.Fatalf("policy missing path %s", prefix)
		}
	}
}

func TestLiveV096CompleteCorrelationChain(t *testing.T) {
	o, events, alerts, manifest := testLiveFiles(t)
	writeJSONL(t, events, map[string]string{"event_id": "token"}, map[string]string{"event_id": "net"})
	writeJSONL(t, alerts, model.SecurityAlert{AlertID: "R007-chain", RuleID: "R007", RelatedEventIDs: []string{"token", "net"}})
	writeManifest(t, manifest, Manifest{SchemaVersion: "1.0", Trials: []Trial{{ID: "chain", Scenario: "credentials", Label: "positive", EventIDs: []string{"token", "net"}}}})
	r, e := EvaluateLive(o)
	if e != nil {
		t.Fatal(e)
	}
	if r.TP != 1 || r.Trials[0].Confusion != "TP" {
		t.Fatalf("full evidence should pass strict attribution: %+v", r)
	}
}

func TestLatencyQuantilesAreInterpolated(t *testing.T) {
	v := latencyStats([]float64{1, 2, 3})
	if v.Samples != 3 || *v.P50Ms != 2 || *v.P95Ms < 2.899 || *v.P95Ms > 2.901 || *v.P99Ms < 2.979 || *v.P99Ms > 2.981 {
		t.Fatalf("unexpected quantiles: %+v", v)
	}
}
