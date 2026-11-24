package detection

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestDistinctIPAggregationDoesNotMixClusters(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "X", Name: "network", Enabled: true, Severity: "high", EventType: "network.connect", DistinctDestinations: 2, WindowSeconds: 30, DestinationCIDRs: []string{"10.0.0.0/8"}}}}
	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	event := func(id, cluster, ip string) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: "network.connect", Timestamp: t0.Format(time.RFC3339Nano), Node: "node-a", Sensor: &model.Sensor{ID: id, Cluster: cluster}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}, Network: &model.Network{DestinationIP: ip}}
	}
	for _, v := range []model.SecurityEvent{event("one", "A", "10.0.0.1"), event("two", "B", "10.0.0.2")} {
		a, err := engine.Evaluate(v)
		if err != nil || len(a) > 0 {
			t.Fatalf("unexpected cross-cluster network aggregation %v %v", a, err)
		}
	}
	a, err := engine.Evaluate(event("three", "A", "10.0.0.3"))
	if err != nil || len(a) != 1 {
		t.Fatalf("same cluster should aggregate: %v %v", a, err)
	}
}
