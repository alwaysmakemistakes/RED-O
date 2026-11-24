package multisensor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestValidateRequiresExplicitSourcesAndDistinctNames(t *testing.T) {
	good := Config{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "node-a", Type: "tetra", Cluster: "k3s", Namespace: "kube-system", Pod: "tetragon-a"}, {ID: "audit", Type: "audit", Cluster: "k3s", Path: "/tmp/audit.log"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []Config{
		{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "x", Type: "tetra", Cluster: "k3s", Namespace: "kube-system"}, {ID: "y", Type: "audit", Cluster: "k3s", Path: "a"}}},
		{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "x", Type: "jsonl", Cluster: "k3s", Path: "a"}, {ID: "x", Type: "jsonl", Cluster: "k3s", Path: "b"}}},
		{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "x", Type: "jsonl", Cluster: "k3s", Path: "a"}, {ID: "y", Type: "audit", Cluster: "k3s", Path: "a"}}},
		{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "x", Type: "jsonl", Cluster: "", Path: "a"}, {ID: "y", Type: "audit", Cluster: "k3s", Path: "b"}}},
	}
	for _, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("expected validation error for %+v", c)
		}
	}
}
func TestIndependentFileStreams(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "b.jsonl")}
	for i, p := range paths {
		if err := os.WriteFile(p, []byte(`{"stream":`+string(rune('0'+i))+`}`+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{SchemaVersion: "1.0", Sensors: []Sensor{{ID: "one", Type: "jsonl", Cluster: "k3s", Path: paths[0]}, {ID: "two", Type: "jsonl", Cluster: "k3s", Path: paths[1]}}}
	var mu sync.Mutex
	got := map[string]int{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, cfg, func(r Record) error {
		var raw map[string]any
		if err := json.Unmarshal(r.Data, &raw); err != nil {
			return err
		}
		if r.ReceivedAt.IsZero() {
			t.Error("missing ingress timestamp")
		}
		mu.Lock()
		got[r.Sensor.ID]++
		mu.Unlock()
		return nil
	}, func(time.Time) error { return nil }, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got["one"] != 1 || got["two"] != 1 {
		t.Fatalf("missing sensor stream %+v", got)
	}
}
