package exception

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestScopedEventException(t *testing.T) {
	a := model.SecurityAlert{RuleID: "R005", Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "ebpf-test"}}
	e := Entry{ID: "EX", Enabled: true, RuleID: "R005", Namespace: "security-lab", Pod: "ebpf-test", Field: "file.path", Value: "/etc/passwd", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Reason: "test"}
	events := []model.SecurityEvent{{File: &model.File{Path: "/etc/passwd"}}}
	if !SuppressedWithEvents([]Entry{e}, a, events, time.Now()) {
		t.Fatal("should suppress")
	}
	if SuppressedWithEvents([]Entry{e}, a, []model.SecurityEvent{{File: &model.File{Path: "/etc/shadow"}}}, time.Now()) {
		t.Fatal("unrelated file suppressed")
	}
	e.Field = "invalid.field"
	if e.Valid() == nil {
		t.Fatal("unsupported field accepted")
	}
}
