package correlation

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestCorrelationIsScopedByClusterEvenWithSameNodeAndContainerIDs(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "X1", Name: "exec + file", Enabled: true, Severity: "high", Description: "test", WindowSeconds: 10, Steps: []Step{{EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}, {EventType: "file.access", PathIn: []string{"/etc/passwd"}}}}}}
	c, err := NewWithLateness(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	makeE := func(id, typ, cluster string, secs int) model.SecurityEvent {
		e := model.SecurityEvent{EventID: id, EventType: typ, Timestamp: at.Add(time.Duration(secs) * time.Second).Format(time.RFC3339Nano), Node: "node-a", Sensor: &model.Sensor{ID: id, Cluster: cluster}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: "same", ContainerID: "same"}, Process: model.Process{Binary: "/bin/sh"}, File: &model.File{Path: "/etc/passwd"}}
		return e
	}
	for _, e := range []model.SecurityEvent{makeE("exec-cluster-a", "process.exec", "cluster-a", 0), makeE("file-cluster-b", "file.access", "cluster-b", 1)} {
		alerts, err := c.Observe(e)
		if err != nil || len(alerts) != 0 {
			t.Fatalf("cross-cluster contamination: %v %v", alerts, err)
		}
	}
	alerts, err := c.Observe(makeE("file-cluster-a", "file.access", "cluster-a", 2))
	if err != nil || len(alerts) != 1 {
		t.Fatalf("same-cluster sequence absent: %v %v", alerts, err)
	}
}
