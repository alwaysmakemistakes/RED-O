package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime-detector/internal/model"
	"strings"
	"testing"
)

func sample(id string) model.SecurityEvent {
	return model.SecurityEvent{EventID: id, EventType: "process.exec", SchemaVersion: "1.1"}
}
func alert(ids ...string) model.SecurityAlert {
	return model.SecurityAlert{AlertID: "alert", RelatedEventIDs: ids}
}
func TestModes(t *testing.T) {
	for _, mode := range []Mode{Forensic, SOC, Lightweight} {
		t.Run(string(mode), func(t *testing.T) {
			var raw, events, alerts bytes.Buffer
			r, e := NewRouter(mode, &raw, &events, &alerts, false, 10)
			if e != nil {
				t.Fatal(e)
			}
			r.ObserveRaw([]byte(`{"test":1}`))
			r.ObserveEvent(sample("a"))
			if mode == SOC {
				r.ObserveEvent(sample("b"))
			}
			if e = r.ObserveAlert(alert("a")); e != nil {
				t.Fatal(e)
			}
			if !json.Valid(alerts.Bytes()[:len(bytes.TrimSpace(alerts.Bytes()))]) {
				t.Fatal("invalid alert JSON")
			}
			switch mode {
			case Forensic:
				if raw.Len() == 0 || events.Len() == 0 {
					t.Fatal("forensic missing output")
				}
			case SOC:
				if raw.Len() != 0 || !strings.Contains(events.String(), `"event_id":"a"`) || strings.Contains(events.String(), `"event_id":"b"`) {
					t.Fatal(events.String())
				}
			case Lightweight:
				if raw.Len() != 0 || events.Len() != 0 {
					t.Fatal("lightweight wrote events")
				}
			}
		})
	}
}
func TestSOCCorrelationRelatedIds(t *testing.T) {
	var events, alerts bytes.Buffer
	r, _ := NewRouter(SOC, nil, &events, &alerts, false, 10)
	for _, id := range []string{"a", "b", "c"} {
		if err := r.ObserveEvent(sample(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.ObserveAlert(alert("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	if err := r.ObserveAlert(alert("a", "c")); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(events.String(), "\n"); n != 3 {
		t.Fatalf("expected 3 unique relevant events; got %d", n)
	}
}
func TestSOCMissingReferenceFails(t *testing.T) {
	var events, alerts bytes.Buffer
	r, _ := NewRouter(SOC, nil, &events, &alerts, false, 1)
	r.ObserveEvent(sample("a"))
	r.ObserveEvent(sample("b"))
	if err := r.ObserveAlert(alert("a", "b")); err == nil {
		t.Fatal("expected overflow failure")
	}
	if alerts.Len() != 0 {
		t.Fatal("orphan alert written")
	}
}
func TestSOCRawOptIn(t *testing.T) {
	var raw, events, alerts bytes.Buffer
	r, _ := NewRouter(SOC, &raw, &events, &alerts, true, 3)
	if err := r.ObserveRaw([]byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw.String(), "ok") {
		t.Fatal("raw missing")
	}
}

func TestSOCEmittedCacheBounded(t *testing.T) {
	var events, alerts bytes.Buffer
	const limit = 8
	r, err := NewRouter(SOC, nil, &events, &alerts, false, limit)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("e-%d", i)
		if err := r.ObserveEvent(sample(id)); err != nil {
			t.Fatal(err)
		}
		if err := r.ObserveAlert(alert(id)); err != nil {
			t.Fatal(err)
		}
		if len(r.emitted) > 2*limit || len(r.cache) > limit {
			t.Fatalf("unbounded state at %d: emitted=%d cache=%d", i, len(r.emitted), len(r.cache))
		}
	}
}
