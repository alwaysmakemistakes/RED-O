package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"runtime-detector/internal/model"
)

type Mode string

const (
	Forensic    Mode = "forensic"
	SOC         Mode = "soc"
	Lightweight Mode = "lightweight"
)

func ParseMode(v string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(v)))
	switch m {
	case Forensic, SOC, Lightweight:
		return m, nil
	default:
		return "", fmt.Errorf("invalid mode %q (choose forensic, soc, lightweight)", v)
	}
}

type Router struct {
	Mode    Mode
	Raw     io.Writer
	Events  io.Writer
	Alerts  io.Writer
	SOCRaw  bool
	Limit   int
	cache   map[string]model.SecurityEvent
	order   []string
	emitted map[string]bool
	// emittedOrder bounds the de-duplication window to recent events.
	emittedOrder []string
}

func NewRouter(mode Mode, raw, events, alerts io.Writer, socRaw bool, limit int) (*Router, error) {
	if _, err := ParseMode(string(mode)); err != nil {
		return nil, err
	}
	if alerts == nil {
		return nil, errors.New("alerts writer required")
	}
	if mode == Forensic && (raw == nil || events == nil) {
		return nil, errors.New("forensic needs raw and events writers")
	}
	if mode == SOC && events == nil {
		return nil, errors.New("soc needs events writer")
	}
	if mode == SOC && limit < 1 {
		return nil, errors.New("soc cache size must be positive")
	}
	if mode == SOC && socRaw && raw == nil {
		return nil, errors.New("soc raw enabled but no raw writer")
	}
	return &Router{Mode: mode, Raw: raw, Events: events, Alerts: alerts, SOCRaw: socRaw, Limit: limit, cache: make(map[string]model.SecurityEvent), emitted: make(map[string]bool)}, nil
}
func (r *Router) ObserveRaw(line []byte) error {
	if r.Mode == Forensic || (r.Mode == SOC && r.SOCRaw) {
		return WriteRaw(r.Raw, line)
	}
	return nil
}
func (r *Router) ObserveEvent(e model.SecurityEvent) error {
	switch r.Mode {
	case Forensic:
		return WriteJSON(r.Events, e)
	case SOC:
		if e.EventID == "" {
			return errors.New("event without event_id")
		}
		if _, ok := r.cache[e.EventID]; !ok {
			r.order = append(r.order, e.EventID)
		}
		r.cache[e.EventID] = e
		for len(r.order) > r.Limit {
			old := r.order[0]
			r.order = r.order[1:]
			delete(r.cache, old)
		}
	}
	return nil
}
func (r *Router) ObserveAlert(a model.SecurityAlert) error {
	if r.Mode == SOC {
		// Fail rather than persist an alert pointing to an unexported event.
		for _, id := range a.RelatedEventIDs {
			if !r.emitted[id] {
				if _, ok := r.cache[id]; !ok {
					return fmt.Errorf("soc reference %s is not cached; increase -soc-buffer", id)
				}
			}
		}
		for _, id := range a.RelatedEventIDs {
			if !r.emitted[id] {
				if err := WriteJSON(r.Events, r.cache[id]); err != nil {
					return err
				}
				r.emitted[id] = true
				r.emittedOrder = append(r.emittedOrder, id)
				// Old IDs are forgotten only when already outside the event cache.
				// Keeping up to 2*Limit covers short-lived overlapping alerts.
				for len(r.emittedOrder) > 2*r.Limit {
					old := r.emittedOrder[0]
					r.emittedOrder = r.emittedOrder[1:]
					delete(r.emitted, old)
				}
			}
		}
	}
	return WriteJSON(r.Alerts, a)
}

// ValidateOutput is useful to check emitted JSON without relying on OS specifics.
func ValidateOutput(line []byte) bool { return json.Valid(line) }
