package detection

import (
	"runtime-detector/internal/model"
	"strings"
	"testing"
)

func TestRuleEngine(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "R001", Name: "shell", Enabled: true, Severity: "medium", EventType: "process.exec", BinaryIn: []string{"/bin/sh"}, NamespaceAllow: []string{"security-lab"}}, {ID: "R002", Name: "file", Enabled: true, Severity: "high", EventType: "file.access", PathIn: []string{"/etc/shadow"}}}}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := model.SecurityEvent{EventID: "event-1", EventType: "process.exec", Timestamp: "2026-10-17T14:29:03Z", Process: model.Process{Binary: "/bin/sh"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab"}}
	alerts, err := eng.Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != "R001" || alerts[0].RelatedEventIDs[0] != "event-1" {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
	if alerts[0].AlertID == "" {
		t.Fatal("empty alert ID")
	}
	e.Kubernetes.Namespace = "kube-system"
	alerts, err = eng.Evaluate(e)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("namespace filter failed: %v %+v", err, alerts)
	}
	e.Kubernetes.Namespace = "security-lab"
	e.EventType = "file.access"
	e.File = &model.File{Path: "/etc/shadow"}
	alerts, err = eng.Evaluate(e)
	if err != nil || len(alerts) != 1 || !strings.Contains(alerts[0].Reason, "success not established") {
		t.Fatalf("file rule failed: %v %+v", err, alerts)
	}
}
func TestRejectBadConfig(t *testing.T) {
	cases := []Config{{Rules: []Rule{{ID: "R1", Name: "bad", Severity: "critical", EventType: "process.exec"}}}, {Rules: []Rule{{ID: "R1", Name: "a", Severity: "low", EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}, {ID: "R1", Name: "b", Severity: "low", EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}}}}
	for _, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatal("expected validation error")
		}
	}
}
