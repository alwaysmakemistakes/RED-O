package heartbeat

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestReport(t *testing.T) {
	f := filepath.Join(t.TempDir(), "hb.json")
	r := New(f, "tetra")
	r.Connected()
	r.Event()
	r.Disconnected(errors.New("broken"))
	r.Connected()
	if e := r.Write(); e != nil {
		t.Fatal(e)
	}
	s, e := Read(f)
	if e != nil {
		t.Fatal(e)
	}
	if !s.Connected || s.Reconnects != 1 || s.EventsReceived != 1 || s.LastEventAt == nil {
		t.Fatalf("bad state %+v", s)
	}
}
