package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCountersAndHistogram(t *testing.T) {
	r := New()
	r.Received()
	r.Normalized()
	r.Alert(time.Now().Add(-10 * time.Millisecond).UTC().Format(time.RFC3339Nano))
	r.Suppressed()
	r.Processing(2 * time.Millisecond)
	r.Correlation(3, 2, 1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, nil)
	for _, x := range []string{"redo_events_received_total 1", "redo_events_normalized_total 1", "redo_alerts_total 1", "redo_alerts_suppressed_total 1", "redo_correlation_pending_events 3", "redo_correlation_late_dropped_total 2", "redo_correlation_forced_released_total 1", "redo_detection_latency_seconds_count 1", "redo_processing_duration_seconds_count 1"} {
		if !strings.Contains(w.Body.String(), x) {
			t.Fatalf("missing %s", x)
		}
	}
}
func TestFutureTimestampExcluded(t *testing.T) {
	r := New()
	r.Alert(time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, nil)
	if !strings.Contains(w.Body.String(), "redo_detection_clock_skew_total 1") || !strings.Contains(w.Body.String(), "redo_detection_latency_seconds_count 0") {
		t.Fatal(w.Body.String())
	}
}

func TestMultiSensorMetrics(t *testing.T) {
	r := New()
	r.SensorReceived("node-a")
	r.SensorReceived("node-a")
	r.SensorReceived("audit")
	r.SensorMerge(12, 3, 2, 1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, nil)
	for _, v := range []string{`redo_sensor_records_received_total{sensor_id="node-a"} 2`, `redo_sensor_records_received_total{sensor_id="audit"} 1`, `redo_sensor_merge_pending_events 12`, `redo_sensor_merge_late_total 3`, `redo_sensor_merge_forced_total 2`, `redo_sensor_future_skew_total 1`} {
		if !strings.Contains(w.Body.String(), v) {
			t.Fatalf("metric %s not found", v)
		}
	}
}
