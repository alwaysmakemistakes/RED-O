package tests

import (
	"path/filepath"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/model"
	"runtime-detector/internal/normalizer"
	"testing"
	"time"
)

// These are labelled unit fixtures: they verify matching logic, not a real
// Kubernetes compromise, successful privilege escalation, or escape.
func TestExtendedThreatIndicators(t *testing.T) {
	cfg, err := detection.Load(filepath.Join("..", "configs", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detection.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(kind, binary, args, path, ip string, port uint32) model.SecurityEvent {
		return model.SecurityEvent{EventID: "fixture", EventType: kind, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Process:    model.Process{Binary: binary, Arguments: args, ExecID: "proc"},
			Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: "pod", ContainerID: "ctr"},
			File:       &model.File{Path: path}, Network: &model.Network{DestinationIP: ip, DestinationPort: port}}
	}
	auditRaw := []byte(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"abc","stage":"ResponseComplete","stageTimestamp":"2026-11-18T10:00:00Z","verb":"create","user":{"username":"system:serviceaccount:security-lab:demo"},"objectRef":{"resource":"pods","namespace":"security-lab","name":"extra"},"responseStatus":{"code":201}}`)
	audit, err := normalizer.Normalize(auditRaw)
	if err != nil {
		t.Fatal(err)
	}
	if audit.EventType != "k8s.audit" || audit.Audit.User != "system:serviceaccount:security-lab:demo" {
		t.Fatalf("audit normalization: %+v", audit)
	}
	cases := []struct {
		name, id string
		event    model.SecurityEvent
		hit      bool
	}{
		{"inline-shell", "R009", mk("process.exec", "/bin/sh", "-c id", "", "", 0), true},
		{"noninline-shell", "R009", mk("process.exec", "/bin/sh", "-i", "", "", 0), false},
		{"credential-token-dynamic", "R010", mk("file.access", "/usr/local/bin/python", "", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_18/token", "", 0), true},
		{"credential-negative-ca", "R010", mk("file.access", "/usr/local/bin/python", "", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_18/ca.crt", "", 0), false},
		{"privilege-capset", "R011", mk("kernel.hook", "/usr/bin/sudo", "", "", "", 0), true},
		{"privilege-tool", "R018", mk("process.exec", "/usr/bin/setcap", "", "", "", 0), true},
		{"namespace-escape-indicator", "R012", mk("process.exec", "/usr/bin/nsenter", "--target 1", "", "", 0), true},
		{"runtime-socket", "R017", mk("file.access", "/bin/cat", "", "/run/containerd/containerd.sock", "", 0), true},
		{"internal-network", "R013", mk("network.connect", "/bin/wget", "", "", "10.43.1.20", 443), true},
		{"external-network", "R013", mk("network.connect", "/bin/wget", "", "", "1.1.1.1", 443), false},
		{"miner-exec", "R014", mk("process.exec", "/tmp/xmrig", "", "", "", 0), true},
		{"miner-pool-port", "R015", mk("network.connect", "/bin/wget", "", "", "203.0.113.3", 3333), true},
		{"network-discovery", "R019", mk("process.exec", "/usr/bin/nmap", "", "", "", 0), true},
		{"audit-created-pod", "R016", audit, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.event
			if tc.id == "R011" {
				ev.Function = "security_capset"
			}
			found, err := engine.Evaluate(ev)
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, a := range found {
				if a.RuleID == tc.id {
					got = true
				}
			}
			if got != tc.hit {
				t.Fatalf("%s: got=%v want=%v alerts=%+v", tc.id, got, tc.hit, found)
			}
		})
	}
	negativeAudit := audit
	negativeAudit.Audit = &model.Audit{Verb: "create", Resource: "pods", User: "test", ResponseCode: 403, Stage: "ResponseComplete"}
	alerts, _ := engine.Evaluate(negativeAudit)
	for _, a := range alerts {
		if a.RuleID == "R016" {
			t.Fatal("denied API request treated as created workload")
		}
	}
	wrongNS := audit
	wrongNS.Kubernetes = &model.Kubernetes{Namespace: "default"}
	alerts, _ = engine.Evaluate(wrongNS)
	for _, a := range alerts {
		if a.RuleID == "R016" {
			t.Fatal("namespace allowlist bypassed")
		}
	}
}

func TestNetworkCorrelationInternalAndIsolation(t *testing.T) {
	cfg, err := correlation.Load("../configs/correlations.json")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, kind, exec, parent, ip, container string, second int) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: kind, Timestamp: time.Date(2026, 11, 18, 10, 0, second, 0, time.UTC).Format(time.RFC3339Nano),
			Process:    model.Process{ExecID: exec, ParentExecID: parent, Binary: "/bin/sh"},
			Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: container, ContainerID: container},
			Network:    &model.Network{DestinationIP: ip, DestinationPort: 443}}
	}
	for _, tc := range []struct {
		name, ip, container string
		expect              bool
	}{
		{"linked-private", "10.42.0.10", "c", true},
		{"public", "1.1.1.1", "c", false},
		{"other-container", "10.42.0.10", "other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := correlation.NewWithLateness(cfg, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			shell := mk("shell", "process.exec", "parent", "", "", "c", 0)
			connection := mk("connect", "network.connect", "child", "parent", tc.ip, tc.container, 1)
			c.Observe(connection)
			c.Observe(shell)
			alerts, err := c.Flush()
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, a := range alerts {
				if a.RuleID == "R020" {
					got = true
				}
			}
			if got != tc.expect {
				t.Fatalf("got R020=%v want=%v", got, tc.expect)
			}
		})
	}
}

func TestAuditRejectsNonFinalStage(t *testing.T) {
	_, err := normalizer.Normalize([]byte(`{"kind":"Event","auditID":"abc","stage":"RequestReceived","stageTimestamp":"2026-11-18T10:00:00Z"}`))
	if err != normalizer.ErrUnsupportedEvent {
		t.Fatalf("expected ignored nonfinal stage, got %v", err)
	}
}

func TestInternalNetworkSweepDistinctDestinationWindow(t *testing.T) {
	cfg, err := detection.Load("../configs/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	newEngine := func() *detection.Engine {
		e, err := detection.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	mk := func(id, ip, pod string, sec int) model.SecurityEvent {
		return model.SecurityEvent{EventID: id, EventType: "network.connect", Timestamp: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second).Format(time.RFC3339Nano),
			Process: model.Process{ExecID: "p"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: pod, ContainerID: pod}, Network: &model.Network{DestinationIP: ip, DestinationPort: 443}}
	}
	count := func(e *detection.Engine, v model.SecurityEvent) int {
		a, err := e.Evaluate(v)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, x := range a {
			if x.RuleID == "R021" {
				count++
			}
		}
		return count
	}
	e := newEngine()
	for i := 1; i <= 4; i++ {
		if count(e, mk("step", "10.42.0."+string(rune('0'+i)), "a", i)) != 0 {
			t.Fatal("early network sweep alert")
		}
	}
	if count(e, mk("dup", "10.42.0.1", "a", 5)) != 0 {
		t.Fatal("repeated destination counts as new")
	}
	if count(e, mk("fifth", "10.42.0.5", "a", 6)) != 1 {
		t.Fatal("missing R021 threshold alert")
	}
	if count(e, mk("sixth", "10.42.0.6", "a", 7)) != 0 {
		t.Fatal("duplicate alert within cooldown")
	}
	e = newEngine()
	for i := 1; i <= 4; i++ {
		count(e, mk("other", "10.42.0."+string(rune('0'+i)), "a", i))
	}
	if count(e, mk("other-pod", "10.42.0.5", "b", 6)) != 0 {
		t.Fatal("cross-container count")
	}
	e = newEngine()
	for i := 1; i <= 4; i++ {
		count(e, mk("old", "10.42.0."+string(rune('0'+i)), "a", i))
	}
	if count(e, mk("late", "10.42.0.5", "a", 70)) != 0 {
		t.Fatal("out-of-window count")
	}
}

func TestTetragonReportedPrivilegeChange(t *testing.T) {
	raw := []byte(`{"time":"2026-11-18T10:00:00Z","process_exec":{"process":{"exec_id":"abc","binary":"/usr/bin/sudo","binary_properties":{"privileges_changed":["PRIVILEGES_RAISED_EXEC_FILE_SETUID"]},"pod":{"namespace":"security-lab","name":"test","uid":"pod","container":{"id":"container"}}}}}`)
	event, err := normalizer.Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := detection.Load("../configs/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := detection.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := e.Evaluate(event)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "R022" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected R022 on Tetragon privileges_changed, got %+v", alerts)
	}
	event.Process.PrivilegesChanged = []string{"PRIVILEGES_DROPPED_EXEC_FILE_CAP"}
	alerts, _ = e.Evaluate(event)
	for _, a := range alerts {
		if a.RuleID == "R022" {
			t.Fatal("privilege drop matched raise")
		}
	}
}
