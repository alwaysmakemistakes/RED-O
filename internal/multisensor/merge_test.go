package multisensor

import (
	"testing"
	"time"

	"runtime-detector/internal/model"
)

func when(n int) time.Time { return time.Date(2026, 11, 18, 10, 0, n, 0, time.UTC) }
func ev(id string, at time.Time) model.SecurityEvent {
	return model.SecurityEvent{EventID: id, Timestamp: at.Format(time.RFC3339Nano)}
}
func TestMultiSensorWatermarkPreventsFastSourceFromOvertakingSlowSource(t *testing.T) {
	start := when(0)
	m, err := NewMerger([]string{"fast", "slow"}, 2*time.Second, 4*time.Second, 20, start)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Observe("fast", ev("later", when(5)), start.Add(time.Second))
	if err != nil || len(a) != 0 {
		t.Fatalf("should await first slow sensor timestamp: %v %v", a, err)
	}
	a, err = m.Observe("slow", ev("earlier", when(2)), start.Add(2*time.Second))
	if err != nil || len(a) != 0 {
		t.Fatalf("late source should constrain watermark: %v %v", a, err)
	}
	a, err = m.Observe("slow", ev("next", when(8)), start.Add(2500*time.Millisecond))
	if err != nil || len(a) != 1 || a[0].EventID != "earlier" {
		t.Fatalf("unexpected release: %v %v", a, err)
	}
	a, err = m.Observe("fast", ev("future", when(10)), start.Add(2600*time.Millisecond))
	if err != nil || len(a) != 1 || a[0].EventID != "later" {
		t.Fatalf("unexpected cross-stream ordering: %v %v", a, err)
	}
	a = m.Flush()
	if len(a) != 2 || a[0].EventID != "next" || a[1].EventID != "future" {
		t.Fatalf("flush order %v", a)
	}
}
func TestIdleAndEndPermitProgress(t *testing.T) {
	start := when(0)
	m, _ := NewMerger([]string{"a", "b"}, time.Second, 3*time.Second, 100, start)
	out, _ := m.Observe("a", ev("one", when(1)), start.Add(time.Second))
	if len(out) != 0 {
		t.Fatal(out)
	}
	out = m.Tick(start.Add(5 * time.Second))
	if len(out) != 1 || out[0].EventID != "one" {
		t.Fatalf("idle sensor stalled forever: %v", out)
	}
	if _, err := m.Finish("unknown", start); err == nil {
		t.Fatal("expected unknown source error")
	}
}
func TestBoundedBufferNoSilentDrop(t *testing.T) {
	start := when(0)
	m, _ := NewMerger([]string{"a", "b"}, time.Second, 10*time.Second, 2, start)
	for i := 1; i < 5; i++ {
		_, err := m.Observe("a", ev(string(rune('0'+i)), when(i)), start.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	stats := m.Stats()
	if stats.Forced != 2 || stats.Pending != 2 {
		t.Fatalf("expected bounded force-release, got %+v", stats)
	}
}
func TestLateAccountingAndTimezone(t *testing.T) {
	start := when(0)
	m, _ := NewMerger([]string{"a", "b"}, 0, 2*time.Second, 10, start)
	out, _ := m.Observe("a", ev("new", when(10)), start.Add(time.Second))
	if len(out) != 0 {
		t.Fatal(out)
	}
	_ = m.Tick(start.Add(4 * time.Second))
	out, _ = m.Observe("a", ev("old", when(1)), start.Add(4500*time.Millisecond))
	if len(out) != 1 || m.Stats().Late != 1 {
		t.Fatalf("late should be tracked, not silently lost: %+v %+v", out, m.Stats())
	}
}
