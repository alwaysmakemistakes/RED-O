package ingester

import (
	"context"
	"encoding/json"
	"log"
	"runtime-detector/internal/clickhouse"
	"runtime-detector/internal/metricsscrape"
	"time"
)

type metricsWriter struct {
	scraper  *metricsscrape.Scraper
	instance string
	interval time.Duration
}

func newMetricsWriter(endpoint, instance string, interval time.Duration) (*metricsWriter, error) {
	if endpoint == "" {
		return nil, nil
	}
	s, err := metricsscrape.New(endpoint)
	if err != nil {
		return nil, err
	}
	return &metricsWriter{scraper: s, instance: instance, interval: interval}, nil
}
func (m *metricsWriter) sample(ctx context.Context, db *clickhouse.Client) error {
	values, err := m.scraper.Scrape(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return db.StoreMetrics(writeCtx, m.instance, time.Now().UTC(), payload)
}
func (m *metricsWriter) run(ctx context.Context, db *clickhouse.Client) {
	if err := m.sample(ctx, db); err != nil && ctx.Err() == nil {
		log.Printf("ingester metrics: %v", err)
	}
	tick := time.NewTicker(m.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := m.sample(ctx, db); err != nil && ctx.Err() == nil {
				log.Printf("ingester metrics: %v", err)
			}
		}
	}
}
