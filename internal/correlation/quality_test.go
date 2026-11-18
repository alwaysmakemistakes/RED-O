package correlation

import (
	"path/filepath"
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestNewIncidentRulesAndProcessIsolation(t *testing.T) {
	cfg, e := Load(filepath.Join("..", "..", "configs", "correlations.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		id, kind, binary, path string
		unrelated              bool
	}{{"R006", "process.exec", "/bin/sh", "", false}, {"R007", "file.access", "/bin/cat", "/var/run/secrets/kubernetes.io/serviceaccount/token", false}, {"R008", "process.exec", "/bin/wget", "", false}, {"R006", "process.exec", "/bin/sh", "", true}} {
		t.Run(test.id+map[bool]string{true: "-unrelated", false: "-related"}[test.unrelated], func(t *testing.T) {
			c, err := NewWithLateness(cfg, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
			start := model.SecurityEvent{EventID: "start", EventType: test.kind, Timestamp: base.Format(time.RFC3339Nano), Node: "main", Process: model.Process{ExecID: "root", Binary: test.binary}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"}, File: &model.File{Path: test.path}}
			net := model.SecurityEvent{EventID: "connect", EventType: "network.connect", Timestamp: base.Add(time.Second).Format(time.RFC3339Nano), Node: "main", Process: model.Process{ExecID: "child", ParentExecID: "root", Binary: "/usr/bin/curl"}, Kubernetes: start.Kubernetes, Network: &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 443}}
			if test.unrelated {
				net.Process.ParentExecID = "other"
			}
			// Deliberately out of arrival order to verify event-time ordering.
			if _, err = c.Observe(net); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Observe(start); err != nil {
				t.Fatal(err)
			}
			alerts, err := c.Flush()
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, a := range alerts {
				if a.RuleID == test.id {
					found++
					if len(a.RelatedEventIDs) != 2 || a.RelatedEventIDs[0] != "start" || a.RelatedEventIDs[1] != "connect" {
						t.Fatalf("bad evidence %+v", a)
					}
				}
			}
			if test.unrelated && found != 0 || !test.unrelated && found != 1 {
				t.Fatalf("rule %s got %d matching alerts %+v", test.id, found, alerts)
			}
		})
	}
}
func TestNewRulesRejectOtherNamespace(t *testing.T) {
	cfg, err := Load("../../configs/correlations.json")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New(cfg)
	e := sample("e", "process.exec", "", "", "c", time.Now().Format(time.RFC3339Nano))
	e.Kubernetes.Namespace = "default"
	e.Process.Binary = "/bin/sh"
	_, err = c.Observe(e)
	if err != nil {
		t.Fatal(err)
	}
	e.EventID = "net"
	e.EventType = "network.connect"
	e.Network.DestinationIP = "1.1.1.1"
	e.Timestamp = time.Now().Add(time.Second).Format(time.RFC3339Nano)
	got, _ := c.Observe(e)
	if len(got) != 0 {
		t.Fatal(got)
	}
}
