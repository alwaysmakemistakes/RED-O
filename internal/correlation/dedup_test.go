package correlation

import (
	"path/filepath"
	"runtime-detector/internal/model"
	"testing"
	"time"
)

// Duplicate token-open observations should not cause duplicate R007 incidents
// when they end at the same TCP event. Separate TCP events remain separate.
func TestR007DeduplicatesSameTerminalEvent(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "correlations.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithLateness(cfg, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
	kube := &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}
	mkFile := func(id string, offset time.Duration) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: "file.access", Timestamp: base.Add(offset).Format(time.RFC3339Nano), Node: "main", Kubernetes: kube,
			Process: model.Process{ExecID: "python", Binary: "/usr/local/bin/python3"},
			File:    &model.File{Path: "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10_14_54_18.3445112349/token"}}
	}
	mkNet := func(id string, offset time.Duration) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: "network.connect", Timestamp: base.Add(offset).Format(time.RFC3339Nano), Node: "main", Kubernetes: kube,
			Process: model.Process{ExecID: "python", Binary: "/usr/local/bin/python3"},
			Network: &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 80}}
	}
	for _, e := range []model.SecurityEvent{mkNet("net1", 2*time.Second), mkFile("file1", 0), mkFile("file2", time.Second)} {
		if _, err := c.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, a := range alerts {
		if a.RuleID == "R007" {
			count++
			if len(a.RelatedEventIDs) != 2 || a.RelatedEventIDs[1] != "net1" {
				t.Fatalf("invalid evidence: %+v", a)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 R007, got %d: %+v", count, alerts)
	}
	// Replaying the same terminal event must not result in a second incident.
	c.observeOrdered(mkFile("file3", 3*time.Second))
	replay, err := c.observeOrdered(mkNet("net1", 4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range replay {
		if a.RuleID == "R007" {
			t.Fatal("duplicate incident on replay", a)
		}
	}
	// A new token access followed by a new TCP event is a distinct incident.
	if _, err := c.observeOrdered(mkFile("file4", 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	next, err := c.observeOrdered(mkNet("net2", 6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var newR007 int
	for _, a := range next {
		if a.RuleID == "R007" {
			newR007++
		}
	}
	if newR007 != 1 {
		t.Fatalf("expected separate incident for net2, got %d", newR007)
	}
}

func TestCorrelationTerminalDedupIsRuleScopedAndBounded(t *testing.T) {
	cfg := Config{Rules: []Rule{
		{ID: "TEST1", Name: "one", Enabled: true, Severity: "high", WindowSeconds: 30, Steps: []Step{{EventType: "file.access"}, {EventType: "network.connect"}}},
		{ID: "TEST2", Name: "two", Enabled: true, Severity: "high", WindowSeconds: 30, Steps: []Step{{EventType: "file.access"}, {EventType: "network.connect"}}},
	}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.maxCompleted = 2
	kube := &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}
	base := time.Now().UTC()
	makeEvent := func(id, kind string, i int) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: kind, Timestamp: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano), Node: "main", Kubernetes: kube, Process: model.Process{ExecID: "python"}}
	}
	var total int
	for i := 0; i < 3; i++ {
		_, _ = c.Observe(makeEvent("file"+string(rune('a'+i)), "file.access", 2*i))
		found, err := c.Observe(makeEvent("net"+string(rune('a'+i)), "network.connect", 2*i+1))
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 2 {
			t.Fatalf("expected one per rule, got %+v", found)
		}
		total += len(found)
	}
	if total != 6 {
		t.Fatal(total)
	}
	b := c.buckets["main|pod|ctr"]
	if b == nil || len(b.completed) > 2 || len(b.completedOrder) > 2 {
		t.Fatalf("unbounded completed history: %+v", b)
	}
}
