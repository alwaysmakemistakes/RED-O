package correlation

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func TestProcessTreeSeparatesIndependentExecutions(t *testing.T) {
	cfg := Config{Rules: []Rule{{ID: "TREE", Name: "Tree", Enabled: true, Severity: "high", WindowSeconds: 60, ProcessTree: true, Steps: []Step{{EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}, {EventType: "file.access", PathIn: []string{"/etc/passwd"}}, {EventType: "network.connect", DestinationIPs: []string{"1.1.1.1"}}}}}}
	newEvent := func(id, typ, exec, parent string, sec int) model.SecurityEvent {
		e := sample(id, typ, "/etc/passwd", "1.1.1.1", "c", time.Date(2026, 10, 20, 12, 0, sec, 0, time.UTC).Format(time.RFC3339Nano))
		e.Process.ExecID = exec
		e.Process.ParentExecID = parent
		return e
	}
	t.Run("siblings under shell", func(t *testing.T) {
		c, _ := New(cfg)
		c.Observe(newEvent("a", "process.exec", "root", "", 0))
		c.Observe(newEvent("b", "file.access", "child1", "root", 1))
		alerts, err := c.Observe(newEvent("c", "network.connect", "child2", "root", 2))
		if err != nil || len(alerts) != 1 {
			t.Fatalf("wanted 1 alert, got %v, %v", alerts, err)
		}
	})
	t.Run("unrelated process", func(t *testing.T) {
		c, _ := New(cfg)
		c.Observe(newEvent("a", "process.exec", "root", "", 0))
		c.Observe(newEvent("b", "file.access", "other", "", 1))
		alerts, err := c.Observe(newEvent("c", "network.connect", "child2", "root", 2))
		if err != nil || len(alerts) != 0 {
			t.Fatalf("unexpected alert %v %v", alerts, err)
		}
	})
	t.Run("unrelated network", func(t *testing.T) {
		c, _ := New(cfg)
		c.Observe(newEvent("a", "process.exec", "root", "", 0))
		c.Observe(newEvent("b", "file.access", "child1", "root", 1))
		alerts, err := c.Observe(newEvent("c", "network.connect", "other", "", 2))
		if err != nil || len(alerts) != 0 {
			t.Fatalf("unexpected alert %v %v", alerts, err)
		}
	})
}
