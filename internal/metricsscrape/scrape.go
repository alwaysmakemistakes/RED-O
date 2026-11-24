// Package metricsscrape provides loopback-only reads of RED-O detector metrics.
// It is shared by the independent Ingester and the Web availability monitor.
package metricsscrape

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var names = []string{
	"redo_events_received_total", "redo_events_normalized_total", "redo_alerts_total", "redo_alerts_suppressed_total",
	"redo_events_invalid_total", "redo_events_unsupported_total", "redo_correlation_pending_events",
	"redo_correlation_late_dropped_total", "redo_correlation_forced_released_total",
	"redo_processing_duration_seconds_count", "redo_processing_duration_seconds_sum",
	"redo_detection_latency_seconds_count", "redo_detection_latency_seconds_sum",
	"redo_process_cpu_seconds_total", "redo_process_heap_alloc_bytes", "redo_process_peak_resident_memory_bytes", "redo_process_uptime_seconds",
}

// ValidateEndpoint prevents the Ingester and Web from scraping remote URLs.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/metrics" {
		return fmt.Errorf("detector metrics must be a loopback HTTP URL ending in /metrics")
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil || (host != "127.0.0.1" && host != "[::1]" && host != "::1" && host != "localhost") {
		return fmt.Errorf("detector metrics must use loopback host:port")
	}
	return nil
}

func Parse(r io.Reader) (map[string]float64, error) {
	allowed := make(map[string]bool, len(names))
	for _, key := range names {
		allowed[key] = true
	}
	values := make(map[string]float64)
	scanner := bufio.NewScanner(io.LimitReader(r, 2<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 || !allowed[parts[0]] {
			continue
		}
		n, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid metric %s: %w", parts[0], err)
		}
		values[parts[0]] = n
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if _, ok := values["redo_events_received_total"]; !ok {
		return nil, fmt.Errorf("detector metrics missing received counter")
	}
	return values, nil
}

type Scraper struct {
	endpoint string
	client   *http.Client
}

func New(endpoint string) (*Scraper, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return &Scraper{endpoint: endpoint, client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (s *Scraper) Scrape(ctx context.Context) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("detector returned HTTP %d", resp.StatusCode)
	}
	return Parse(resp.Body)
}
