package correlation

import (
	"path/filepath"
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestR007ProjectedTokenPaths(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "correlations.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path string
		want       bool
	}{
		{"kube projected token", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10_14_54_18.3445112349/token", true},
		{"direct run token", "/run/secrets/kubernetes.io/serviceaccount/token", true},
		{"direct var run token", "/var/run/secrets/kubernetes.io/serviceaccount/token", true},
		{"ca crt", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10_14_54_18.3445112349/ca.crt", false},
		{"namespace", "/run/secrets/kubernetes.io/serviceaccount/namespace", false},
		{"suffix attack", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10/token.bak", false},
		{"other volume", "/tmp/serviceaccount/token", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewWithLateness(cfg, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
			kube := &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}
			file := model.SecurityEvent{EventID: "file", EventType: "file.access", Timestamp: base.Format(time.RFC3339Nano), Node: "main", Kubernetes: kube, Process: model.Process{ExecID: "py", Binary: "/usr/local/bin/python3"}, File: &model.File{Path: tt.path}}
			conn := model.SecurityEvent{EventID: "network", EventType: "network.connect", Timestamp: base.Add(time.Second).Format(time.RFC3339Nano), Node: "main", Kubernetes: kube, Process: model.Process{ExecID: "py", Binary: "/usr/local/bin/python3"}, Network: &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 80}}
			// Network arrives first but event time is later.
			if _, err := c.Observe(conn); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Observe(file); err != nil {
				t.Fatal(err)
			}
			alerts, err := c.Flush()
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, alert := range alerts {
				if alert.RuleID != "R007" {
					continue
				}
				count++
				if len(alert.RelatedEventIDs) != 2 || alert.RelatedEventIDs[0] != "file" || alert.RelatedEventIDs[1] != "network" {
					t.Fatalf("bad R007 evidence: %+v", alert)
				}
			}
			if (count == 1) != tt.want || count > 1 {
				t.Fatalf("R007 count %d, expected %v", count, tt.want)
			}
		})
	}
}

func TestR007UnrelatedProcessDoesNotCorrelate(t *testing.T) {
	cfg, err := Load("../../configs/correlations.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithLateness(cfg, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
	kube := &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}
	file := model.SecurityEvent{EventID: "file", EventType: "file.access", Timestamp: base.Format(time.RFC3339Nano), Node: "main", Kubernetes: kube, Process: model.Process{ExecID: "py", Binary: "/usr/local/bin/python3"}, File: &model.File{Path: "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10/token"}}
	net := model.SecurityEvent{EventID: "net", EventType: "network.connect", Timestamp: base.Add(time.Second).Format(time.RFC3339Nano), Node: "main", Kubernetes: kube, Process: model.Process{ExecID: "unrelated", ParentExecID: "other", Binary: "/usr/local/bin/python3"}, Network: &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 80}}
	_, _ = c.Observe(file)
	_, _ = c.Observe(net)
	alerts, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.RuleID == "R007" {
			t.Fatalf("unrelated processes correlated: %+v", a)
		}
	}
}

func TestPathRegexValidation(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "RX", Name: "invalid regex", Enabled: true, Severity: "high", WindowSeconds: 30, Steps: []Step{{EventType: "file.access", PathRegex: "[invalid"}, {EventType: "network.connect"}}}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid regex accepted")
	}
	cfg.Rules[0].Steps[0].PathRegex = "^/token$"
	cfg.Rules[0].Steps[0].EventType = "process.exec"
	if err := cfg.Validate(); err == nil {
		t.Fatal("path regex on non-file step accepted")
	}
}
