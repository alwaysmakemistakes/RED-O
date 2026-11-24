package contextpolicy

import (
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"testing"
)

func makeEvent(id, pod, arg string) model.SecurityEvent {
	return model.SecurityEvent{EventID: id, Timestamp: "2026-11-21T17:39:53Z", Sensor: &model.Sensor{Cluster: "lab-k3s"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: pod}, Process: model.Process{Binary: "/bin/sh", Arguments: arg}}
}
func TestContextApprovedRequiresExactEvidence(t *testing.T) {
	cfg := Config{SchemaVersion: "1.0", Policies: []Policy{{ID: "approved-shell", Enabled: true, Decision: "approved", Reason: "independently recorded change", RuleIDs: []string{"R001", "R009"}, Match: Match{Cluster: "lab-k3s", Namespace: "security-lab", Pod: "ebpf-test", ProcessBinary: "/bin/sh", ArgumentsContains: "approved-trial-foo"}, ValidFrom: "2026-11-21T17:00:00Z", ValidUntil: "2026-11-21T18:00:00Z"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a := model.SecurityAlert{RuleID: "R001", Severity: "medium", RelatedEventIDs: []string{"one"}}
	ev := makeEvent("one", "ebpf-test", "-c approved-trial-foo")
	d := cfg.Assess(a, []model.SecurityEvent{ev}, true)
	if d.Decision != "approved" || d.TriageAction != "approved" || d.RiskScore != 20 || d.OriginalSeverity != "medium" {
		t.Fatalf("incorrect approved enrichment %+v", d)
	}
	d = cfg.Assess(a, []model.SecurityEvent{ev}, false)
	if d.TriageAction != "review" || d.Decision != "incomplete_evidence" {
		t.Fatalf("missing evidence allowed %+v", d)
	}
	ev.Process.Arguments = "-c other-marker"
	if d = cfg.Assess(a, []model.SecurityEvent{ev}, true); d.Decision != "unmatched" {
		t.Fatalf("wrong command matched %+v", d)
	}
	ev = makeEvent("one", "other-pod", "-c approved-trial-foo")
	if d = cfg.Assess(a, []model.SecurityEvent{ev}, true); d.Decision != "unmatched" {
		t.Fatalf("wrong pod matched %+v", d)
	}
	ev = makeEvent("one", "ebpf-test", "-c approved-trial-foo")
	ev.Timestamp = "2026-11-21T18:01:00Z"
	if d = cfg.Assess(a, []model.SecurityEvent{ev}, true); d.Decision != "unmatched" {
		t.Fatalf("expired policy matched %+v", d)
	}
	a.RelatedEventIDs = []string{"one", "two"}
	a.Severity = "critical"
	ev = makeEvent("one", "ebpf-test", "-c approved-trial-foo")
	other := makeEvent("two", "elsewhere", "-c approved-trial-foo")
	if d = cfg.Assess(a, []model.SecurityEvent{ev, other}, true); d.Decision != "unmatched" {
		t.Fatalf("mixed scope matched %+v", d)
	}
}
func TestPolicyConfigurationSafety(t *testing.T) {
	c := Config{SchemaVersion: "1.0", Policies: []Policy{{ID: "p", Enabled: true, Decision: "approved", Reason: "test", RuleIDs: []string{"R010"}, Match: Match{Namespace: "security-lab"}}}}
	if err := c.Validate(); err == nil {
		t.Fatal("blanket approval unexpectedly accepted")
	}
	c.Policies[0].Match.Pod = "test-pod"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Policies = append(c.Policies, c.Policies[0])
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate IDs accepted")
	}
	c.Policies = c.Policies[:1]
	c.Policies[0].Match.DestinationCIDR = "hello"
	if err := c.Validate(); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1.0","policies":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
func TestElevateAuditAndScoring(t *testing.T) {
	c := Config{SchemaVersion: "1.0", Policies: []Policy{{ID: "risk", Enabled: true, Decision: "elevate", Reason: "sensitive", RuleIDs: []string{"R016"}, Match: Match{Namespace: "security-lab", AuditUser: "system:admin", AuditName: "pod-x"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := model.SecurityEvent{EventID: "x", Kubernetes: &model.Kubernetes{Namespace: "security-lab"}, Audit: &model.Audit{User: "system:admin", Name: "pod-x"}}
	a := model.SecurityAlert{RuleID: "R016", Severity: "high", RelatedEventIDs: []string{"x"}}
	d := c.Assess(a, []model.SecurityEvent{ev}, true)
	if d.Decision != "elevate" || d.TriageAction != "review" || d.RiskScore != 95 || d.RiskLevel != "critical" {
		t.Fatalf("risk not elevated %+v", d)
	}
}
