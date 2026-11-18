package heartbeat

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State describes collector liveness. A connected state means the tetra child
// process is running; it does not prove end-to-end lossless delivery.
type State struct {
	Version            int        `json:"version"`
	UpdatedAt          time.Time  `json:"updated_at"`
	StartedAt          time.Time  `json:"started_at"`
	Source             string     `json:"source"`
	Node               string     `json:"node,omitempty"`
	Connected          bool       `json:"connected"`
	LastConnectedAt    *time.Time `json:"last_connected_at,omitempty"`
	LastDisconnectedAt *time.Time `json:"last_disconnected_at,omitempty"`
	LastEventAt        *time.Time `json:"last_event_at,omitempty"`
	EventsReceived     uint64     `json:"events_received"`
	Reconnects         uint64     `json:"reconnects"`
	LastError          string     `json:"last_error,omitempty"`
	// Delivery gaps represent periods with no live Collector stream, not a count
	// of missed Tetragon events. Existing version-1 readers ignore these fields.
	Disconnections       uint64     `json:"disconnections"`
	CompletedGaps        uint64     `json:"completed_gaps"`
	TotalGapMilliseconds int64      `json:"total_gap_ms"`
	CurrentGapStartedAt  *time.Time `json:"current_gap_started_at,omitempty"`
	LastGapMilliseconds  int64      `json:"last_gap_ms,omitempty"`
}

type Reporter struct {
	mu        sync.Mutex
	path      string
	state     State
	attempted bool
	clock     func() time.Time
}

func New(path, source string) *Reporter {
	host, _ := os.Hostname()
	return &Reporter{path: path, clock: time.Now, state: State{Version: 1, StartedAt: time.Now().UTC(), Source: source, Node: host}}
}

// Gap is a completed period with no live Collector stream. It is not proof
// that events were emitted or lost during that time.
type Gap struct {
	StartedAt            time.Time `json:"started_at"`
	EndedAt              time.Time `json:"ended_at"`
	DurationMilliseconds int64     `json:"duration_ms"`
	Node                 string    `json:"node,omitempty"`
	Source               string    `json:"source"`
}

// Connected closes a gap if a prior stream ended or failed to start.
// The optional result can be written to an append-only incident journal.
func (r *Reporter) Connected() *Gap {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.clock().UTC()
	var result *Gap
	if r.state.CurrentGapStartedAt != nil {
		begin := *r.state.CurrentGapStartedAt
		duration := t.Sub(begin)
		if duration < 0 {
			duration = 0
		}
		ms := duration.Milliseconds()
		result = &Gap{StartedAt: begin, EndedAt: t, DurationMilliseconds: ms, Node: r.state.Node, Source: r.state.Source}
		r.state.CompletedGaps++
		r.state.TotalGapMilliseconds += ms
		r.state.LastGapMilliseconds = ms
		r.state.CurrentGapStartedAt = nil
	}
	if r.attempted || result != nil {
		r.state.Reconnects++
	}
	r.attempted = true
	r.state.Connected = true
	r.state.LastConnectedAt = &t
	r.state.LastError = ""
	return result
}
func (r *Reporter) Disconnected(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.clock().UTC()
	if r.state.Connected || r.state.CurrentGapStartedAt == nil {
		r.state.Disconnections++
	}
	r.state.Connected = false
	r.state.LastDisconnectedAt = &t
	if r.state.CurrentGapStartedAt == nil {
		r.state.CurrentGapStartedAt = &t
	}
	if err != nil {
		r.state.LastError = err.Error()
	}
}

// Stop marks intentional shutdown without counting it as a transport failure.
func (r *Reporter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Connected = false
	r.state.CurrentGapStartedAt = nil
}

// AppendGap records a recovered interruption. A failed write is surfaced to
// the caller, rather than silently claiming the incident was persisted.
func AppendGap(path string, gap Gap) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.Marshal(gap)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
func (r *Reporter) Event() {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := time.Now().UTC()
	r.state.LastEventAt = &t
	r.state.EventsReceived++
}
func (r *Reporter) Snapshot() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state
	s.UpdatedAt = time.Now().UTC()
	return s
}
func (r *Reporter) Write() error {
	if r.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(r.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteAtomic(r.path, data)
}
func WriteAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".heartbeat-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("publish heartbeat: %w", err)
	}
	return nil
}
func Read(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	if err != nil {
		return s, err
	}
	if s.Version != 1 || s.UpdatedAt.IsZero() {
		return s, fmt.Errorf("invalid heartbeat schema")
	}
	return s, nil
}
