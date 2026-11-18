package correlation

import (
	"runtime-detector/internal/model"
	"testing"
	"time"
)

func delayedEvent(id, typ, exe, parent string, second int) model.SecurityEvent {
	e := sample(id, typ, "/etc/passwd", "1.1.1.1", "container-a", time.Date(2026, 11, 10, 10, 0, second, 0, time.UTC).Format(time.RFC3339Nano))
	e.Process.ExecID = exe
	e.Process.ParentExecID = parent
	return e
}
func delayedRule() Config {
	return Config{Rules: []Rule{{ID: "R005", Name: "chain", Enabled: true, Severity: "critical", WindowSeconds: 60, ProcessTree: true, Steps: []Step{{EventType: "process.exec", BinaryIn: []string{"/bin/sh"}}, {EventType: "file.access", PathIn: []string{"/etc/passwd"}}, {EventType: "network.connect", DestinationIPs: []string{"1.1.1.1"}}}}}}
}

func TestEventTimeReorderAndFlush(t *testing.T) {
	c, err := NewWithLateness(delayedRule(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sequence := []model.SecurityEvent{
		delayedEvent("net", "network.connect", "wget", "shell", 3),
		delayedEvent("shell", "process.exec", "shell", "", 0),
		delayedEvent("file", "file.access", "id", "shell", 2),
	}
	for _, e := range sequence {
		alerts, err := c.Observe(e)
		if err != nil {
			t.Fatal(err)
		}
		if len(alerts) != 0 {
			t.Fatalf("premature alerts: %+v", alerts)
		}
	}
	a, err := c.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(a))
	}
	want := []string{"shell", "file", "net"}
	for i, id := range want {
		if a[0].RelatedEventIDs[i] != id {
			t.Fatalf("order %v", a[0].RelatedEventIDs)
		}
	}
	if x, err := c.Flush(); err != nil || len(x) != 0 {
		t.Fatalf("duplicate on flush: %v %v", x, err)
	}
}
func TestEventTimeWatermarkAndLateDrop(t *testing.T) {
	c, _ := NewWithLateness(delayedRule(), 2*time.Second)
	for _, e := range []model.SecurityEvent{delayedEvent("shell", "process.exec", "shell", "", 0), delayedEvent("net", "network.connect", "wget", "shell", 4)} {
		if _, err := c.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	// The process.exec at t=0 was committed once t=4 arrived.
	_, err := c.Observe(delayedEvent("too-late", "file.access", "id", "shell", -1))
	if err != nil {
		t.Fatal(err)
	}
	if c.Stats().LateDropped != 1 {
		t.Fatalf("wanted 1 late drop: %+v", c.Stats())
	}
}
func TestEventTimeIdleFlush(t *testing.T) {
	c, _ := NewWithLateness(delayedRule(), 3*time.Second)
	for _, e := range []model.SecurityEvent{delayedEvent("shell", "process.exec", "shell", "", 0), delayedEvent("file", "file.access", "id", "shell", 1), delayedEvent("net", "network.connect", "wget", "shell", 2)} {
		if _, err := c.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	if a, err := c.FlushIdle(time.Now().Add(5 * time.Second)); err != nil || len(a) != 1 {
		t.Fatalf("idle: %v %v", a, err)
	}
}
func TestEventTimeUnrelatedProcess(t *testing.T) {
	c, _ := NewWithLateness(delayedRule(), 5*time.Second)
	for _, e := range []model.SecurityEvent{delayedEvent("net", "network.connect", "wget", "shell", 3), delayedEvent("file", "file.access", "id", "other", 2), delayedEvent("shell", "process.exec", "shell", "", 0)} {
		if _, err := c.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	a, err := c.Flush()
	if err != nil || len(a) != 0 {
		t.Fatalf("false correlation: %v %v", a, err)
	}
}
func TestEventTimeBounded(t *testing.T) {
	c, _ := NewWithLateness(delayedRule(), time.Minute)
	c.maxPending = 2
	for i := 0; i < 4; i++ {
		e := delayedEvent(string(rune('a'+i)), "process.exec", "shell", "", i)
		if _, err := c.Observe(e); err != nil {
			t.Fatal(err)
		}
	}
	if s := c.Stats(); s.Pending != 2 || s.ForcedReleased != 2 {
		t.Fatalf("unexpected stats: %+v", s)
	}
}
