// Package metrics exposes low-cardinality RED-O process and detection metrics.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var latencyBuckets = [...]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	Count   uint64
	Sum     float64
	Buckets [len(latencyBuckets)]uint64
}

func (h *histogram) observe(d time.Duration) {
	s := d.Seconds()
	if s < 0 {
		return
	}
	h.Count++
	h.Sum += s
	for i, v := range latencyBuckets {
		if s <= v {
			h.Buckets[i]++
		}
	}
}

type Registry struct {
	sensors                                                        map[string]uint64
	sensorPending                                                  int
	sensorLate, sensorForced, sensorFutureSkew                     uint64
	mu                                                             sync.Mutex
	started                                                        time.Time
	received, normalized, invalid, unsupported, alerts, suppressed uint64
	processed                                                      histogram
	detection                                                      histogram
	clockSkew                                                      uint64
	pending                                                        int
	lateDropped, forcedReleased                                    uint64
}

func New() *Registry                         { return &Registry{started: time.Now(), sensors: map[string]uint64{}} }
func (r *Registry) SensorReceived(id string) { r.mu.Lock(); defer r.mu.Unlock(); r.sensors[id]++ }
func (r *Registry) SensorMerge(pending int, late, forced, futureSkew uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sensorPending = pending
	r.sensorLate = late
	r.sensorForced = forced
	r.sensorFutureSkew = futureSkew
}
func (r *Registry) Received()    { r.mu.Lock(); r.received++; r.mu.Unlock() }
func (r *Registry) Normalized()  { r.mu.Lock(); r.normalized++; r.mu.Unlock() }
func (r *Registry) Invalid()     { r.mu.Lock(); r.invalid++; r.mu.Unlock() }
func (r *Registry) Unsupported() { r.mu.Lock(); r.unsupported++; r.mu.Unlock() }
func (r *Registry) Alert(ts string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts++
	if t, e := time.Parse(time.RFC3339Nano, ts); e == nil {
		d := time.Since(t)
		if d < 0 {
			r.clockSkew++
		} else {
			r.detection.observe(d)
		}
	}
}
func (r *Registry) Suppressed()                { r.mu.Lock(); r.suppressed++; r.mu.Unlock() }
func (r *Registry) Processing(d time.Duration) { r.mu.Lock(); r.processed.observe(d); r.mu.Unlock() }
func (r *Registry) Correlation(pending int, late, forced uint64) {
	r.mu.Lock()
	r.pending = pending
	r.lateDropped = late
	r.forcedReleased = forced
	r.mu.Unlock()
}
func printHistogram(b *strings.Builder, name, help string, h histogram) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, v := range latencyBuckets {
		fmt.Fprintf(b, "%s_bucket{le=\"%g\"} %d\n", name, v, h.Buckets[i])
	}
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", name, h.Count, name, h.Sum, name, h.Count)
}

// ServeHTTP is read-only. The caller must bind the server to a trusted loopback address.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	a := struct {
		received, normalized, invalid, unsupported, alerts, suppressed, clockSkew uint64
		processed, detection                                                      histogram
		pending                                                                   int
		lateDropped, forcedReleased                                               uint64
		started                                                                   time.Time
	}{r.received, r.normalized, r.invalid, r.unsupported, r.alerts, r.suppressed, r.clockSkew, r.processed, r.detection, r.pending, r.lateDropped, r.forcedReleased, r.started}
	sensorCounters := make(map[string]uint64, len(r.sensors))
	for k, v := range r.sensors {
		sensorCounters[k] = v
	}
	sensorPending, sensorLate, sensorForced, sensorFutureSkew := r.sensorPending, r.sensorLate, r.sensorForced, r.sensorFutureSkew
	r.mu.Unlock()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	cpu := float64(usage.Utime.Sec) + float64(usage.Utime.Usec)/1e6 + float64(usage.Stime.Sec) + float64(usage.Stime.Usec)/1e6
	var b strings.Builder
	counter := func(name, help string, v uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge := func(name, help string, v interface{}) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, v)
	}
	counter("redo_events_received_total", "Raw event records delivered to handler.", a.received)
	counter("redo_events_normalized_total", "Successfully normalized events.", a.normalized)
	counter("redo_events_invalid_total", "Invalid event records.", a.invalid)
	counter("redo_events_unsupported_total", "Unsupported event types.", a.unsupported)
	counter("redo_alerts_total", "Alerts persisted by detector.", a.alerts)
	counter("redo_alerts_suppressed_total", "Alerts suppressed by configured exceptions.", a.suppressed)
	counter("redo_detection_clock_skew_total", "Alert timestamps later than the detector clock.", a.clockSkew)
	printHistogram(&b, "redo_processing_duration_seconds", "Handler processing duration including output IO.", a.processed)
	printHistogram(&b, "redo_detection_latency_seconds", "Wall time minus last matching event timestamp; includes intentional event-time buffering.", a.detection)
	gauge("redo_correlation_pending_events", "Events pending event-time correlation.", a.pending)
	counter("redo_correlation_late_dropped_total", "Too-late events excluded from correlation.", a.lateDropped)
	counter("redo_correlation_forced_released_total", "Events released early due to buffer limit.", a.forcedReleased)
	gauge("redo_sensor_merge_pending_events", "Events waiting for multi-sensor event-time ordering.", sensorPending)
	counter("redo_sensor_merge_late_total", "Events arriving earlier than the global committed timestamp.", sensorLate)
	counter("redo_sensor_merge_forced_total", "Events force-released due to bounded multi-sensor buffer.", sensorForced)
	counter("redo_sensor_future_skew_total", "Events timestamped more than 30s ahead of receipt; possible unsynchronised clock.", sensorFutureSkew)
	fmt.Fprintf(&b, "# HELP redo_sensor_records_received_total Raw records received by configured sensor.\n# TYPE redo_sensor_records_received_total counter\n")
	ids := make([]string, 0, len(sensorCounters))
	for id := range sensorCounters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "redo_sensor_records_received_total{sensor_id=%q} %d\n", id, sensorCounters[id])
	}
	gauge("redo_process_heap_alloc_bytes", "Go heap allocation in bytes.", mem.HeapAlloc)
	gauge("redo_process_peak_resident_memory_bytes", "Peak resident memory from Getrusage (Linux ru_maxrss in KB).", uint64(usage.Maxrss)*1024)
	fmt.Fprintf(&b, "# HELP redo_process_cpu_seconds_total CPU seconds of detector process.\n# TYPE redo_process_cpu_seconds_total counter\nredo_process_cpu_seconds_total %g\n", cpu)
	gauge("redo_process_uptime_seconds", "Detector process uptime.", time.Since(a.started).Seconds())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
