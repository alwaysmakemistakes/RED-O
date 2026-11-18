package tests

import (
	"path/filepath"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/model"
	"sort"
	"testing"
	"time"
)

// These fixtures are synthetic, not claims of real exploit or attack coverage.
// They exercise actual public rule files and the event-time process-tree pipeline.
var base = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func ev(id, kind, binary, exec, parent, path, ip, namespace, container string, sec int) model.SecurityEvent {
	return model.SecurityEvent{EventID: id, EventType: kind, Timestamp: base.Add(time.Duration(sec) * time.Second).Format(time.RFC3339Nano), Node: "main", Process: model.Process{ExecID: exec, ParentExecID: parent, Binary: binary}, Kubernetes: &model.Kubernetes{Namespace: namespace, Pod: "demo", PodUID: "pod-" + container, ContainerID: container}, File: &model.File{Path: path}, Network: &model.Network{DestinationIP: ip, DestinationPort: 443}}
}

type scenario struct {
	name     string
	events   []model.SecurityEvent
	expected []string
}

func TestAllRulesAndNegativeScenarios(t *testing.T) {
	rules, err := detection.Load(filepath.Join("..", "configs", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Retain the original 9-scenario golden baseline for R001–R008;
	// extended scenario tests cover the new indicator catalogue separately.
	legacy := rules.Rules[:0]
	for _, rule := range rules.Rules {
		if rule.ID >= "R001" && rule.ID <= "R008" {
			legacy = append(legacy, rule)
		}
	}
	rules.Rules = legacy
	engine, err := detection.New(rules)
	if err != nil {
		t.Fatal(err)
	}
	correlations, err := correlation.Load(filepath.Join("..", "configs", "correlations.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := correlations.Rules[:0]
	for _, rule := range correlations.Rules {
		if rule.ID >= "R001" && rule.ID <= "R008" {
			old = append(old, rule)
		}
	}
	correlations.Rules = old
	shell := ev("shell", "process.exec", "/bin/sh", "shell", "", "", "", "security-lab", "a", 0)
	file := ev("file", "file.access", "/bin/cat", "reader", "shell", "/etc/passwd", "", "security-lab", "a", 1)
	netEvent := ev("net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "a", 2)
	tokenNet := netEvent
	tokenNet.Process.ParentExecID = "reader"
	token := ev("token", "file.access", "/bin/cat", "reader", "shell", "/var/run/secrets/kubernetes.io/serviceaccount/token", "", "security-lab", "a", 1)
	wget := ev("wget", "process.exec", "/bin/wget", "wget", "", "", "", "security-lab", "a", 0)
	wgetNet := ev("wget-net", "network.connect", "/bin/wget", "wget", "", "", "1.1.1.1", "security-lab", "a", 1)
	tests := []scenario{
		{"shell-file-network-reordered", []model.SecurityEvent{netEvent, shell, file}, []string{"R001", "R003", "R005", "R006"}},
		{"token-network", []model.SecurityEvent{tokenNet, token}, []string{"R002", "R003", "R007"}},
		{"wget-network", []model.SecurityEvent{wgetNet, wget}, []string{"R003", "R004", "R008"}},
		{"sensitive-file-only", []model.SecurityEvent{ev("shadow", "file.access", "/bin/cat", "cat", "", "/etc/shadow", "", "security-lab", "a", 0)}, []string{"R002"}},
		{"shell-unrelated-process", []model.SecurityEvent{shell, ev("other-net", "network.connect", "/bin/wget", "other", "other-root", "", "1.1.1.1", "security-lab", "a", 1)}, []string{"R001", "R003"}},
		{"different-container", []model.SecurityEvent{shell, ev("external-net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "b", 1)}, []string{"R001", "R003"}},
		{"other-namespace", []model.SecurityEvent{ev("normal", "process.exec", "/bin/sh", "sh", "", "", "", "default", "a", 0), ev("network", "network.connect", "/bin/wget", "wget", "sh", "", "1.1.1.1", "default", "a", 1)}, []string{}},
		{"nonmonitored-ip", []model.SecurityEvent{shell, ev("nonmatch", "network.connect", "/bin/wget", "wget", "shell", "", "9.9.9.9", "security-lab", "a", 1)}, []string{"R001"}},
		{"outside-window", []model.SecurityEvent{shell, ev("late-net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "a", 61)}, []string{"R001", "R003"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corr, err := correlation.NewWithLateness(correlations, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, e := range tt.events {
				alerts, err := engine.Evaluate(e)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range alerts {
					got = append(got, a.RuleID)
				}
				alerts, err = corr.Observe(e)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range alerts {
					got = append(got, a.RuleID)
					if len(a.RelatedEventIDs) < 2 {
						t.Fatal("incomplete correlation evidence")
					}
				}
			}
			remaining, err := corr.Flush()
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range remaining {
				got = append(got, a.RuleID)
				if len(a.RelatedEventIDs) < 2 {
					t.Fatal("incomplete correlation evidence")
				}
			}
			sort.Strings(got)
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("got %v want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v want %v", got, want)
				}
			}
		})
	}
}
