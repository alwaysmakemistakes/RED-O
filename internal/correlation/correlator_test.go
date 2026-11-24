package correlation

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func sample(id, kind, path, ip, container, stamp string) model.SecurityEvent {
	return model.SecurityEvent{EventID: id, EventType: kind, Timestamp: stamp, Node: "n", Process: model.Process{Binary: "/bin/sh"}, Kubernetes: &model.Kubernetes{Namespace: "security-lab", PodUID: "pod1", ContainerID: container}, File: &model.File{Path: path}, Network: &model.Network{DestinationIP: ip}}
}
func TestSequences(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "R005", Name: "sequence", Enabled: true, Severity: "critical", WindowSeconds: 60, Steps: []Step{{EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}, {EventType: "file.access", PathIn: []string{"/etc/passwd"}}, {EventType: "network.connect", DestinationIPs: []string{"1.1.1.1"}}}}}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	put := func(id, k, p, ip, container string, sec int) []model.SecurityAlert {
		t.Helper()
		a, e := c.Observe(sample(id, k, p, ip, container, base.Add(time.Duration(sec)*time.Second).Format(time.RFC3339Nano)))
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	if len(put("1", "process.exec", "", "", "a", 0)) != 0 {
		t.Fatal("premature")
	}
	put("2", "file.access", "/etc/passwd", "", "b", 1)
	put("3", "network.connect", "", "1.1.1.1", "a", 2)
	if len(put("4", "file.access", "/etc/passwd", "", "a", 3)) != 0 {
		t.Fatal("premature")
	}
	alerts := put("5", "network.connect", "", "1.1.1.1", "a", 4)
	if len(alerts) != 1 || len(alerts[0].RelatedEventIDs) != 3 || alerts[0].RelatedEventIDs[0] != "1" || alerts[0].RelatedEventIDs[1] != "4" || alerts[0].RelatedEventIDs[2] != "5" {
		t.Fatalf("bad alert: %+v", alerts)
	}
	if len(put("5", "network.connect", "", "1.1.1.1", "a", 4)) != 0 {
		t.Fatal("duplicate")
	}
}
func TestWindowAndOrder(t *testing.T) {
	c, _ := New(Config{Rules: []Rule{{ID: "X", Name: "X", Enabled: true, Severity: "high", WindowSeconds: 3, Steps: []Step{{EventType: "process.exec"}, {EventType: "network.connect"}}}}})
	a := sample("1", "process.exec", "", "", "c", "2026-10-18T10:00:00Z")
	c.Observe(a)
	b := sample("2", "network.connect", "", "", "c", "2026-10-18T10:00:04Z")
	x, _ := c.Observe(b)
	if len(x) != 0 {
		t.Fatal("expired chain")
	}
	z := sample("3", "process.exec", "", "", "c", "2026-10-18T10:00:01Z")
	x, _ = c.Observe(z)
	if len(x) != 0 {
		t.Fatal("out of order")
	}
}
