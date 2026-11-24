package detectorapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runtime-detector/internal/model"
	"runtime-detector/internal/multisensor"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func rawExec(at string) string {
	return `{"time":"` + at + `","node_name":"node-a","process_exec":{"process":{"exec_id":"exec-shell","pid":1,"binary":"/bin/sh","pod":{"namespace":"security-lab","name":"ebpf-test","uid":"pod-uid","container":{"id":"ctr-id","name":"test"}}}}}`
}
func rawFile(at string) string {
	return `{"time":"` + at + `","node_name":"node-a","process_kprobe":{"function_name":"security_file_open","args":[{"file_arg":{"path":"/etc/passwd"}}],"process":{"exec_id":"exec-cat","parent_exec_id":"exec-shell","pid":2,"binary":"/bin/cat","pod":{"namespace":"security-lab","name":"ebpf-test","uid":"pod-uid","container":{"id":"ctr-id","name":"test"}}}}}`
}
func TestTwoSensorEndToEndOriginAndTemporalCorrelation(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a.jsonl"), filepath.Join(d, "b.jsonl")
	// Source A arrives with later event timestamp, source B with earlier exec.
	if err := os.WriteFile(a, []byte(rawFile("2026-11-18T10:00:02Z")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(rawExec("2026-11-18T13:00:01+03:00")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(d, "sensors.json")
	writeJSON(t, cfgPath, multisensor.Config{SchemaVersion: "1.0", Sensors: []multisensor.Sensor{{ID: "file-sensor", Type: "jsonl", Cluster: "lab", Node: "node-a", Path: a}, {ID: "exec-sensor", Type: "jsonl", Cluster: "lab", Node: "node-a", Path: b}}})
	rulePath := filepath.Join(d, "rules.json")
	writeJSON(t, rulePath, map[string]any{"version": "1.0", "rules": []any{}})
	corrPath := filepath.Join(d, "correlations.json")
	writeJSON(t, corrPath, map[string]any{"correlations": []any{map[string]any{"id": "TEST1", "name": "exec+read", "enabled": true, "severity": "high", "description": "cross sensor", "window_seconds": 10, "steps": []any{map[string]any{"event_type": "process.exec", "binary_in": []string{"/bin/sh"}}, map[string]any{"event_type": "file.access", "path_in": []string{"/etc/passwd"}}}}}})
	previous := sensorConfigPath
	sensorConfigPath = cfgPath
	defer func() { sensorConfigPath = previous }()
	events := filepath.Join(d, "events.jsonl")
	alerts := filepath.Join(d, "alerts.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runModeSourceFiltered(ctx, "multi", "kubectl", "kube-system", "", "-", events, filepath.Join(d, "raw.jsonl"), "", corrPath, alerts, "forensic", false, 100)
	if err != nil {
		t.Fatal(err)
	}
	eventBytes, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(eventBytes)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 normalized records, got %d", len(lines))
	}
	rawBytes, err := os.ReadFile(filepath.Join(d, "raw.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(rawBytes)), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		if v["_redo_origin"] == nil || v["_redo_received_at"] == nil {
			t.Fatalf("forensic raw source missing %v", v)
		}
	}
	seen := map[string]bool{}
	for _, line := range lines {
		var e model.SecurityEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Sensor == nil || e.Sensor.Cluster != "lab" || e.Node != "node-a" || e.ReceivedAt == "" {
			t.Fatalf("missing sensor origin %+v", e)
		}
		if !strings.HasSuffix(e.Timestamp, "Z") {
			t.Fatalf("timestamp not UTC: %s", e.Timestamp)
		}
		seen[e.Sensor.ID] = true
	}
	if !seen["file-sensor"] || !seen["exec-sensor"] {
		t.Fatalf("both streams not preserved %v", seen)
	}
	content, err := os.ReadFile(alerts)
	if err != nil {
		t.Fatal(err)
	}
	var alert model.SecurityAlert
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &alert); err != nil {
		t.Fatalf("expected cross sensor alert, got %q err %v", content, err)
	}
	if alert.RuleID != "TEST1" || alert.Cluster != "lab" || len(alert.SensorIDs) != 2 || alert.SensorIDs[0] != "exec-sensor" || alert.SensorIDs[1] != "file-sensor" {
		t.Fatalf("lost correlated origins %+v", alert)
	}
}
