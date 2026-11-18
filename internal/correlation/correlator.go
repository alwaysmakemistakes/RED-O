// Package correlation detects ordered event sequences within one Kubernetes container.
package correlation

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"runtime-detector/internal/model"
)

type Step struct {
	EventType         string   `json:"event_type"`
	BinaryIn          []string `json:"binary_in,omitempty"`
	PathIn            []string `json:"path_in,omitempty"`
	PathPrefixes      []string `json:"path_prefixes,omitempty"`
	PathRegex         string   `json:"path_regex,omitempty"`
	compiledPathRegex *regexp.Regexp
	DestinationIPs    []string `json:"destination_ips,omitempty"`
	DestinationCIDRs  []string `json:"destination_cidrs,omitempty"`
	compiledCIDRs     []netip.Prefix
	DestinationPorts  []uint32 `json:"destination_ports,omitempty"`
}
type Rule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Severity       string   `json:"severity"`
	Description    string   `json:"description"`
	WindowSeconds  int      `json:"window_seconds"`
	ProcessTree    bool     `json:"process_tree,omitempty"`
	NamespaceAllow []string `json:"namespace_allow,omitempty"`
	Steps          []Step   `json:"steps"`
}
type Config struct {
	Rules []Rule `json:"correlations"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	seen := map[string]bool{}
	allowed := map[string]bool{"process.exec": true, "process.exit": true, "file.access": true, "network.connect": true, "kernel.hook": true}
	levels := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	for _, r := range c.Rules {
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("invalid or duplicate correlation ID %q", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Name) == "" || !levels[r.Severity] || r.WindowSeconds <= 0 || r.WindowSeconds > 86400 || len(r.Steps) < 2 || len(r.Steps) > 12 {
			return fmt.Errorf("invalid correlation rule %s", r.ID)
		}
		for _, s := range r.Steps {
			if !allowed[s.EventType] {
				return fmt.Errorf("rule %s: unsupported step %q", r.ID, s.EventType)
			}
			if len(s.BinaryIn) > 0 && s.EventType != "process.exec" || (len(s.PathIn)+len(s.PathPrefixes) > 0 || s.PathRegex != "") && s.EventType != "file.access" || (len(s.DestinationIPs)+len(s.DestinationPorts)+len(s.DestinationCIDRs) > 0 && s.EventType != "network.connect") {
				return fmt.Errorf("rule %s: incompatible step constraints", r.ID)
			}
			if s.PathRegex != "" {
				if _, err := regexp.Compile(s.PathRegex); err != nil {
					return fmt.Errorf("rule %s: invalid path_regex %q: %w", r.ID, s.PathRegex, err)
				}
			}
			for _, v := range s.DestinationCIDRs {
				if _, err := netip.ParsePrefix(v); err != nil {
					return fmt.Errorf("rule %s: invalid destination CIDR %q: %w", r.ID, v, err)
				}
			}
		}
	}
	return nil
}

type chain struct {
	rule     int
	next     int
	start    time.Time
	last     time.Time
	ids      []string
	rootExec string
}
type bucket struct {
	chains  []chain
	last    time.Time
	parents map[string]string
	// Per-container, per-rule deduplication by terminal event ID.
	completed      map[string]struct{}
	completedOrder []string
}
type Correlator struct {
	rules          []Rule
	buckets        map[string]*bucket
	maxBuckets     int
	maxChains      int
	maxCompleted   int
	maxWindow      time.Duration
	lateness       time.Duration
	pending        map[string]*eventBuffer
	maxPending     int
	lateDropped    uint64
	forcedReleased uint64
}

type pendingEvent struct {
	event     model.SecurityEvent
	timestamp time.Time
	sequence  uint64
}
type eventBuffer struct {
	events      []pendingEvent
	maxSeen     time.Time
	lastEmitted time.Time
	lastArrival time.Time
}

type BufferStats struct {
	Pending        int    `json:"pending"`
	LateDropped    uint64 `json:"late_dropped"`
	ForcedReleased uint64 `json:"forced_released"`
}

func New(cfg Config) (*Correlator, error) {
	if e := cfg.Validate(); e != nil {
		return nil, e
	}
	// Compile regular expressions once at startup; do not pay the compilation cost per event.
	rules := make([]Rule, len(cfg.Rules))
	copy(rules, cfg.Rules)
	for i := range rules {
		rules[i].Steps = append([]Step(nil), cfg.Rules[i].Steps...)
		for j := range rules[i].Steps {
			if pattern := rules[i].Steps[j].PathRegex; pattern != "" {
				rules[i].Steps[j].compiledPathRegex = regexp.MustCompile(pattern)
			}
			for _, v := range rules[i].Steps[j].DestinationCIDRs {
				prefix, _ := netip.ParsePrefix(v)
				rules[i].Steps[j].compiledCIDRs = append(rules[i].Steps[j].compiledCIDRs, prefix)
			}
		}
	}
	c := &Correlator{rules: rules, buckets: make(map[string]*bucket), maxBuckets: 2048, maxChains: 128, maxCompleted: 4096, pending: make(map[string]*eventBuffer), maxPending: 256}
	for _, r := range cfg.Rules {
		d := time.Duration(r.WindowSeconds) * time.Second
		if d > c.maxWindow {
			c.maxWindow = d
		}
	}
	return c, nil
}

// NewWithLateness buffers out-of-order events within each container before correlation.
// A zero value preserves the original synchronous event-by-event behavior.
func NewWithLateness(cfg Config, lateness time.Duration) (*Correlator, error) {
	if lateness < 0 || lateness > time.Minute {
		return nil, fmt.Errorf("lateness must be between 0 and 1 minute")
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	c.lateness = lateness
	return c, nil
}

// SetBufferLimit limits buffered events per container. Overflow forces the
// oldest event to be evaluated and increases forced_released metrics.
func (c *Correlator) SetBufferLimit(n int) error {
	if n < 1 || n > 100000 {
		return fmt.Errorf("correlation buffer must be between 1 and 100000")
	}
	c.maxPending = n
	return nil
}

// Observe processes an incoming event. With lateness enabled, some alerts are
// emitted on later calls to Observe, FlushIdle, or Flush. No goroutine is used.
func (c *Correlator) Observe(e model.SecurityEvent) ([]model.SecurityAlert, error) {
	if c.lateness == 0 {
		return c.observeOrdered(e)
	}
	if e.EventID == "" {
		return nil, fmt.Errorf("missing event_id")
	}
	t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return nil, err
	}
	if e.Kubernetes == nil || e.Kubernetes.ContainerID == "" || e.Kubernetes.PodUID == "" {
		return nil, nil
	}
	key := eventKey(e)
	b := c.pending[key]
	if b == nil {
		b = &eventBuffer{}
		c.pending[key] = b
	}
	if !b.lastEmitted.IsZero() && t.Before(b.lastEmitted) {
		c.lateDropped++
		return nil, nil
	}
	now := time.Now()
	b.lastArrival = now
	if t.After(b.maxSeen) {
		b.maxSeen = t
	}
	b.events = append(b.events, pendingEvent{event: e, timestamp: t})
	sort.SliceStable(b.events, func(i, j int) bool { return b.events[i].timestamp.Before(b.events[j].timestamp) })
	var out []model.SecurityAlert
	// Watermark: events at or before maxSeen - lateness can be committed.
	watermark := b.maxSeen.Add(-c.lateness)
	emitted, err := c.release(key, b, watermark, false)
	out = append(out, emitted...)
	if err != nil {
		return out, err
	}
	// Hard bound: release oldest records on overflow, regardless of watermark.
	for len(b.events) > c.maxPending {
		c.forcedReleased++
		more, er := c.releaseN(key, b, 1)
		out = append(out, more...)
		if er != nil {
			return out, er
		}
	}
	// Bound number of pending containers: flush least-recently-active buffer.
	for len(c.pending) > c.maxBuckets {
		oldest := ""
		for k, v := range c.pending {
			if oldest == "" || v.lastArrival.Before(c.pending[oldest].lastArrival) {
				oldest = k
			}
		}
		more, er := c.release(oldest, c.pending[oldest], time.Time{}, true)
		out = append(out, more...)
		if er != nil {
			return out, er
		}
		delete(c.pending, oldest)
	}
	return out, nil
}

// FlushIdle releases buffered events for containers without arrivals during
// the allowed-lateness interval. Call it periodically for live streams.
func (c *Correlator) FlushIdle(now time.Time) ([]model.SecurityAlert, error) {
	var out []model.SecurityAlert
	for key, b := range c.pending {
		if !now.Before(b.lastArrival.Add(c.lateness)) {
			more, err := c.release(key, b, time.Time{}, true)
			out = append(out, more...)
			if err != nil {
				return out, err
			}
			// Keep lastEmitted for recognizing late arrivals, but bound empty buffers.
		}
	}
	return out, nil
}

// Flush drains all event-time buffers at end-of-file or graceful shutdown.
func (c *Correlator) Flush() ([]model.SecurityAlert, error) {
	var out []model.SecurityAlert
	// Deterministic ordering across containers (the correlation is isolated).
	keys := make([]string, 0, len(c.pending))
	for key := range c.pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		more, err := c.release(key, c.pending[key], time.Time{}, true)
		out = append(out, more...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *Correlator) Stats() BufferStats {
	s := BufferStats{LateDropped: c.lateDropped, ForcedReleased: c.forcedReleased}
	for _, b := range c.pending {
		s.Pending += len(b.events)
	}
	return s
}

func eventKey(e model.SecurityEvent) string {
	return e.Node + "|" + e.Kubernetes.PodUID + "|" + e.Kubernetes.ContainerID
}

func (c *Correlator) release(key string, b *eventBuffer, watermark time.Time, all bool) ([]model.SecurityAlert, error) {
	n := 0
	for n < len(b.events) && (all || !b.events[n].timestamp.After(watermark)) {
		n++
	}
	return c.releaseN(key, b, n)
}
func (c *Correlator) releaseN(key string, b *eventBuffer, n int) ([]model.SecurityAlert, error) {
	var out []model.SecurityAlert
	for i := 0; i < n; i++ {
		item := b.events[i]
		if !b.lastEmitted.IsZero() && item.timestamp.Before(b.lastEmitted) {
			c.lateDropped++
			continue
		}
		found, err := c.observeOrdered(item.event)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
		b.lastEmitted = item.timestamp
	}
	b.events = b.events[n:]
	return out, nil
}

// observeOrdered is the stateful rule evaluator, always fed ordered event time.
func (c *Correlator) observeOrdered(e model.SecurityEvent) ([]model.SecurityAlert, error) {
	if e.EventID == "" {
		return nil, fmt.Errorf("missing event_id")
	}
	t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return nil, err
	}
	if e.Kubernetes == nil || e.Kubernetes.ContainerID == "" || e.Kubernetes.PodUID == "" {
		return nil, nil
	}
	key := eventKey(e)
	b := c.buckets[key]
	if b != nil && t.Before(b.last) {
		return nil, nil
	}
	if b == nil {
		if len(c.buckets) >= c.maxBuckets {
			c.evictOldest()
		}
		b = &bucket{parents: make(map[string]string), completed: make(map[string]struct{})}
		c.buckets[key] = b
	}
	b.last = t
	if b.parents == nil {
		b.parents = make(map[string]string)
	}
	if e.Process.ExecID != "" {
		if _, ok := b.parents[e.Process.ExecID]; !ok {
			b.parents[e.Process.ExecID] = e.Process.ParentExecID
		}
		if len(b.parents) > 4096 {
			b.parents = map[string]string{e.Process.ExecID: e.Process.ParentExecID}
		}
	}
	out := make([]model.SecurityAlert, 0)
	nextChains := make([]chain, 0, len(b.chains)+len(c.rules))
	for _, ch := range b.chains {
		r := c.rules[ch.rule]
		if t.Sub(ch.start) > time.Duration(r.WindowSeconds)*time.Second {
			continue
		}
		if contains(ch.ids, e.EventID) {
			nextChains = append(nextChains, ch)
			continue
		}
		if r.ProcessTree && !descendsFrom(e.Process.ExecID, ch.rootExec, b.parents) {
			nextChains = append(nextChains, ch)
			continue
		}
		if !match(r.Steps[ch.next], e) {
			nextChains = append(nextChains, ch)
			continue
		}
		ch.ids = append(append([]string{}, ch.ids...), e.EventID)
		ch.last = t
		ch.next++
		if ch.next == len(r.Steps) {
			// Several first-step events (e.g. repeated open() calls) may
			// complete on the same network event. Emit one incident per
			// rule and terminal event, without suppressing other rules.
			terminalKey := r.ID + "|" + e.EventID
			if _, already := b.completed[terminalKey]; already {
				continue
			}
			id, er := newUUID()
			if er != nil {
				return nil, er
			}
			if b.completed == nil {
				b.completed = make(map[string]struct{})
			}
			b.completed[terminalKey] = struct{}{}
			b.completedOrder = append(b.completedOrder, terminalKey)
			if len(b.completedOrder) > c.maxCompleted {
				delete(b.completed, b.completedOrder[0])
				b.completedOrder[0] = ""
				b.completedOrder = b.completedOrder[1:]
			}
			out = append(out, model.SecurityAlert{SchemaVersion: "1.0", AlertID: id, RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Status: "firing", Timestamp: e.Timestamp, Description: r.Description, Reason: fmt.Sprintf("Observed %d ordered events in the same container within %ds; this is an indicator, not proof of compromise", len(ch.ids), r.WindowSeconds), Kubernetes: e.Kubernetes, RelatedEventIDs: ch.ids})
		} else {
			nextChains = append(nextChains, ch)
		}
	}
	for i, r := range c.rules {
		if !r.Enabled || len(r.NamespaceAllow) > 0 && !contains(r.NamespaceAllow, e.Kubernetes.Namespace) {
			continue
		}
		if match(r.Steps[0], e) {
			nextChains = append(nextChains, chain{rule: i, next: 1, start: t, last: t, ids: []string{e.EventID}, rootExec: e.Process.ExecID})
		}
	}
	if len(nextChains) > c.maxChains {
		nextChains = nextChains[len(nextChains)-c.maxChains:]
	}
	b.chains = nextChains
	// Reclaim idle buckets using event time. This is a bounded state cache, not a persistent stream processor.
	if len(c.buckets) > 1 {
		for k, v := range c.buckets {
			if k != key && t.Sub(v.last) > c.maxWindow {
				delete(c.buckets, k)
			}
		}
	}
	return out, nil
}
func (c *Correlator) evictOldest() {
	var oldest string
	var at time.Time
	for k, b := range c.buckets {
		if oldest == "" || b.last.Before(at) {
			oldest = k
			at = b.last
		}
	}
	delete(c.buckets, oldest)
}
func contains[T comparable](v []T, x T) bool {
	for _, a := range v {
		if a == x {
			return true
		}
	}
	return false
}
func match(s Step, e model.SecurityEvent) bool {
	if s.EventType != e.EventType {
		return false
	}
	if len(s.BinaryIn) > 0 && !contains(s.BinaryIn, e.Process.Binary) {
		return false
	}
	if len(s.PathIn)+len(s.PathPrefixes) > 0 || s.PathRegex != "" {
		if e.File == nil {
			return false
		}
		ok := contains(s.PathIn, e.File.Path)
		for _, p := range s.PathPrefixes {
			if strings.HasPrefix(e.File.Path, p) {
				ok = true
			}
		}
		if s.PathRegex != "" {
			re := s.compiledPathRegex
			if re == nil { // also support direct match() calls in tests
				re = regexp.MustCompile(s.PathRegex)
			}
			ok = ok || re.MatchString(e.File.Path)
		}
		if !ok {
			return false
		}
	}
	if len(s.DestinationIPs)+len(s.DestinationPorts)+len(s.DestinationCIDRs) > 0 {
		if e.Network == nil {
			return false
		}
		if len(s.DestinationCIDRs) > 0 {
			ip, err := netip.ParseAddr(e.Network.DestinationIP)
			if err != nil {
				return false
			}
			matched := false
			for _, prefix := range s.compiledCIDRs {
				if prefix.Contains(ip) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if len(s.DestinationIPs) > 0 && !contains(s.DestinationIPs, e.Network.DestinationIP) {
			return false
		}
		if len(s.DestinationPorts) > 0 && !contains(s.DestinationPorts, e.Network.DestinationPort) {
			return false
		}
	}
	return true
}

// descendsFrom verifies the process ancestry using Tetragon exec IDs, not PID
// (PIDs can be reused). Sibling processes match when rooted at the shell.
func descendsFrom(execID, root string, parents map[string]string) bool {
	if execID == "" || root == "" {
		return false
	}
	seen := make(map[string]bool)
	for i := 0; i < 128 && execID != ""; i++ {
		if execID == root {
			return true
		}
		if seen[execID] {
			return false
		}
		seen[execID] = true
		execID = parents[execID]
	}
	return false
}
