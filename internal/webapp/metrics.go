package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime-detector/internal/clickhouse"
	"runtime-detector/internal/metricsscrape"
	"sync"
	"time"
)

// metricsMonitor only accesses the explicitly configured loopback detector endpoint.
// It holds a short in-memory rolling series; no collector metrics are fabricated.
type metricsMonitor struct {
	endpoint  string
	client    *http.Client
	mu        sync.RWMutex
	history   []metricSample
	lastError string
	db        *clickhouse.Client
	instance  string
}
type metricSample struct {
	At     time.Time          `json:"at"`
	Values map[string]float64 `json:"values"`
}

func newMetricsMonitor(endpoint string) (*metricsMonitor, error) {
	if endpoint == "" {
		return nil, nil
	}
	if err := metricsscrape.ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return &metricsMonitor{endpoint: endpoint, client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func parseMetrics(r io.Reader) (map[string]float64, error) { return metricsscrape.Parse(r) }
func (m *metricsMonitor) sample(ctx context.Context) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint, nil)
	if e != nil {
		m.recordError(e)
		return
	}
	resp, e := m.client.Do(req)
	if e != nil {
		m.recordError(e)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		m.recordError(fmt.Errorf("detector returned HTTP %d", resp.StatusCode))
		return
	}
	vals, e := parseMetrics(resp.Body)
	if e != nil {
		m.recordError(e)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastError = ""
	now := time.Now().UTC()
	m.history = append(m.history, metricSample{At: now, Values: vals})
	// ClickHouse writes are owned exclusively by the independent Ingester.
	// Keep one hour of samples, up to 720 at five second intervals.
	if len(m.history) > 720 {
		m.history = append([]metricSample(nil), m.history[len(m.history)-720:]...)
	}
}
func (m *metricsMonitor) recordError(e error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastError = e.Error()
}
func (m *metricsMonitor) run(ctx context.Context) {
	m.sample(ctx)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sample(ctx)
		}
	}
}
func (m *metricsMonitor) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "10m"
	}
	if window != "10m" && window != "1h" && window != "24h" {
		http.Error(w, "Invalid window", 400)
		return
	}
	m.mu.RLock()
	samples := append([]metricSample(nil), m.history...)
	lastError := m.lastError
	m.mu.RUnlock()
	// Read persisted snapshots when possible; fall back to RAM if ClickHouse is unavailable.
	if m.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		records, err := m.db.MetricsHistory(ctx, m.instance, window)
		cancel()
		if err == nil {
			loaded := make([]metricSample, 0, len(records))
			for _, row := range records {
				timestamp, _ := row["at"].(string)
				body, _ := row["payload"].(string)
				at, e := time.Parse("2006-01-02T15:04:05", timestamp)
				if e != nil {
					continue
				}
				var values map[string]float64
				if json.Unmarshal([]byte(body), &values) == nil {
					loaded = append(loaded, metricSample{At: at.UTC(), Values: values})
				}
			}
			if len(loaded) > 0 {
				samples = loaded
			}
		} else {
			log.Printf("metrics history query: %v", err)
		}
	}
	// Limit response size and hide the detector endpoint from API callers.
	if len(samples) > 720 {
		samples = samples[len(samples)-720:]
	}
	online := lastError == "" && len(samples) > 0 && time.Since(samples[len(samples)-1].At) < 15*time.Second
	if samples == nil {
		samples = []metricSample{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"available": online, "error": lastError, "samples": samples, "interval_seconds": 5, "window": window})
}
