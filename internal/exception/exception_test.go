package exception

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestScope(t *testing.T) {
	a := model.SecurityAlert{RuleID: "R004", Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "ebpf-test"}}
	es := []Entry{{ID: "x", RuleID: "R004", Namespace: "security-lab", Enabled: true, Reason: "lab", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}}
	if !Suppressed(es, a, time.Now()) {
		t.Fatal("expected match")
	}
	a.RuleID = "R005"
	if Suppressed(es, a, time.Now()) {
		t.Fatal("unexpected match")
	}
}

func TestExpiredExceptionDoesNotBlockUpdates(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/exceptions.json"
	expired := Entry{ID: "old", RuleID: "R003", Namespace: "security-lab", Enabled: true, Reason: "previous exception", ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	active := Entry{ID: "new", RuleID: "R005", Namespace: "security-lab", Enabled: true, Field: "file.path", Value: "/etc/passwd", Reason: "lab test", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := Write(path, []Entry{expired, active}); err != nil {
		t.Fatalf("writing existing expired exception should work: %v", err)
	}
	got, err := Read(path)
	if err != nil || len(got) != 2 {
		t.Fatalf("read exceptions: %v, %d", err, len(got))
	}
	alert := model.SecurityAlert{RuleID: "R005", Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "ebpf-test"}}
	if !SuppressedWithEvents(got, alert, []model.SecurityEvent{{File: &model.File{Path: "/etc/passwd"}}}, time.Now()) {
		t.Fatal("active exception should suppress")
	}
}

func TestCacheReloadsNewException(t *testing.T) {
	path := t.TempDir() + "/exceptions.json"
	cache := NewCache(path)
	alert := model.SecurityAlert{RuleID: "R005", Kubernetes: &model.Kubernetes{Namespace: "security-lab", Pod: "ebpf-test"}}
	ev := []model.SecurityEvent{{File: &model.File{Path: "/etc/passwd"}}}
	if cache.SuppressedWithEvents(alert, ev) {
		t.Fatal("unexpected suppression")
	}
	entry := Entry{ID: "new", RuleID: "R005", Namespace: "security-lab", Pod: "ebpf-test", Enabled: true, Field: "file.path", Value: "/etc/passwd", Reason: "lab", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := Write(path, []Entry{entry}); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	cache.checked = time.Time{}
	cache.mu.Unlock()
	if !cache.SuppressedWithEvents(alert, ev) {
		t.Fatal("reloaded exception should suppress")
	}
}
