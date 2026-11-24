package multisensor

import (
	"container/heap"
	"fmt"
	"sort"
	"time"

	"runtime-detector/internal/model"
)

type buffered struct {
	event model.SecurityEvent
	at    time.Time
	seq   uint64
}
type queue []buffered

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].seq < q[j].seq
	}
	return q[i].at.Before(q[j].at)
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(x any)   { *q = append(*q, x.(buffered)) }
func (q *queue) Pop() any     { last := len(*q) - 1; v := (*q)[last]; *q = (*q)[:last]; return v }

type sensorClock struct {
	maxSeen, arrival time.Time
	done             bool
}
type MergeStats struct {
	Pending    int    `json:"pending"`
	Late       uint64 `json:"late"`
	Forced     uint64 `json:"forced"`
	FutureSkew uint64 `json:"future_skew"`
}

// Merger performs bounded *event-time* ordering across all sensors.
// The watermark is the minimum active sensor's max event-time minus allowed
// lateness. Silent sensors become idle after idleTimeout, allowing progress.
// This is best-effort, not a total-order guarantee for unbounded network delay.
type Merger struct {
	clocks                map[string]*sensorClock
	pending               queue
	lateness, idleTimeout time.Duration
	maxPending            int
	seq                   uint64
	released              time.Time
	stats                 MergeStats
}

func NewMerger(ids []string, lateness, idleTimeout time.Duration, maxPending int, now time.Time) (*Merger, error) {
	if lateness < 0 || lateness > time.Minute {
		return nil, fmt.Errorf("multisensor lateness must be between 0 and 1 minute")
	}
	if idleTimeout <= 0 || idleTimeout > time.Minute {
		return nil, fmt.Errorf("sensor idle timeout must be between 0 and 1 minute")
	}
	if maxPending < 1 || maxPending > 100000 {
		return nil, fmt.Errorf("sensor buffer must be between 1 and 100000")
	}
	m := &Merger{clocks: make(map[string]*sensorClock), lateness: lateness, idleTimeout: idleTimeout, maxPending: maxPending}
	for _, id := range ids {
		if _, ok := m.clocks[id]; ok {
			return nil, fmt.Errorf("duplicate sensor %s", id)
		}
		m.clocks[id] = &sensorClock{arrival: now}
	}
	heap.Init(&m.pending)
	return m, nil
}
func (m *Merger) Observe(id string, e model.SecurityEvent, received time.Time) ([]model.SecurityEvent, error) {
	clock, ok := m.clocks[id]
	if !ok {
		return nil, fmt.Errorf("unknown sensor %q", id)
	}
	t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("sensor %s event time: %w", id, err)
	}
	if clock.done {
		return nil, fmt.Errorf("sensor %s already completed", id)
	}
	// Event times more than 30s in the future are suspicious (unsynchronised
	// sensor clock or erroneous data). Preserve the record, but count the
	// anomaly: detector must not silently invent or rewrite source time.
	if t.After(received.Add(30 * time.Second)) {
		m.stats.FutureSkew++
	}
	clock.arrival = received
	if t.After(clock.maxSeen) {
		clock.maxSeen = t
	}
	m.seq++
	heap.Push(&m.pending, buffered{event: e, at: t, seq: m.seq})
	return m.drain(received, false), nil
}
func (m *Merger) Tick(now time.Time) []model.SecurityEvent { return m.drain(now, false) }
func (m *Merger) Finish(id string, now time.Time) ([]model.SecurityEvent, error) {
	s, ok := m.clocks[id]
	if !ok {
		return nil, fmt.Errorf("unknown sensor %q", id)
	}
	s.done = true
	return m.drain(now, false), nil
}
func (m *Merger) Flush() []model.SecurityEvent { return m.drain(time.Now(), true) }
func (m *Merger) Stats() MergeStats            { s := m.stats; s.Pending = len(m.pending); return s }

func (m *Merger) drain(now time.Time, all bool) []model.SecurityEvent {
	var watermark time.Time
	hasActive := false
	for _, s := range m.clocks {
		if s.done {
			continue
		}
		if now.Sub(s.arrival) >= m.idleTimeout {
			continue
		}
		if s.maxSeen.IsZero() { // Stream has not supplied a first timestamp.
			return m.forceOnly()
		}
		candidate := s.maxSeen.Add(-m.lateness)
		if !hasActive || candidate.Before(watermark) {
			watermark = candidate
		}
		hasActive = true
	}
	// When all sensors are silent or completed, drain all remaining records;
	// idle-time flush prevents indefinite buffering on a quiet cluster.
	if !hasActive {
		all = true
	}
	var out []model.SecurityEvent
	for m.pending.Len() > 0 && (all || !m.pending[0].at.After(watermark)) {
		v := heap.Pop(&m.pending).(buffered)
		if !m.released.IsZero() && v.at.Before(m.released) {
			m.stats.Late++
		}
		if v.at.After(m.released) {
			m.released = v.at
		}
		out = append(out, v.event)
	}
	for m.pending.Len() > m.maxPending {
		m.stats.Forced++
		v := heap.Pop(&m.pending).(buffered)
		if !m.released.IsZero() && v.at.Before(m.released) {
			m.stats.Late++
		}
		if v.at.After(m.released) {
			m.released = v.at
		}
		out = append(out, v.event)
	}
	// Forced releases and watermark releases must still be delivered in event-time order.
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, out[i].Timestamp)
		b, _ := time.Parse(time.RFC3339Nano, out[j].Timestamp)
		return a.Before(b)
	})
	return out
}
func (m *Merger) forceOnly() []model.SecurityEvent {
	var out []model.SecurityEvent
	for m.pending.Len() > m.maxPending {
		m.stats.Forced++
		v := heap.Pop(&m.pending).(buffered)
		if !m.released.IsZero() && v.at.Before(m.released) {
			m.stats.Late++
		}
		if v.at.After(m.released) {
			m.released = v.at
		}
		out = append(out, v.event)
	}
	return out
}
