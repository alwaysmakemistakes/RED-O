// Package ingester owns all persistent ClickHouse writes (JSONL ingestion and
// detector metrics history). The Web process only reads the data.
package ingester

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime-detector/internal/clickhouse"
	"sync"
	"syscall"
	"time"
)

type Options struct {
	ClickHouse, User, Events, Alerts, Offsets, MetricsURL, Instance, LockFile string
	Interval                                                                  time.Duration
}

func Defaults() Options {
	return Options{
		ClickHouse: "http://127.0.0.1:8123", User: "default",
		Events: "data/live-events.jsonl", Alerts: "data/live-alerts.jsonl",
		// Compatibility with v0.9.2: do not silently reset the already committed cursor.
		Offsets: "data/web-offsets.json", MetricsURL: "http://127.0.0.1:9095/metrics",
		Instance: "detector-local", LockFile: "data/ingester.instance.lock", Interval: 5 * time.Second,
	}
}

func Run(args []string) error {
	opts := Defaults()
	fs := flag.NewFlagSet("ingester", flag.ContinueOnError)
	fs.StringVar(&opts.ClickHouse, "clickhouse", opts.ClickHouse, "ClickHouse HTTP endpoint")
	fs.StringVar(&opts.User, "ch-user", opts.User, "ClickHouse user")
	fs.StringVar(&opts.Events, "events", opts.Events, "normalized events JSONL")
	fs.StringVar(&opts.Alerts, "alerts", opts.Alerts, "alerts JSONL")
	fs.StringVar(&opts.Offsets, "offsets", opts.Offsets, "persistent ingestion checkpoint (retains legacy filename)")
	fs.StringVar(&opts.MetricsURL, "detector-metrics", opts.MetricsURL, "loopback detector metrics URL (empty disables capture)")
	fs.StringVar(&opts.Instance, "metrics-instance", opts.Instance, "metrics instance name")
	fs.StringVar(&opts.LockFile, "lock-file", opts.LockFile, "exclusive ingester lock")
	fs.DurationVar(&opts.Interval, "metrics-interval", opts.Interval, "metrics sampling interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected ingester arguments: %v", fs.Args())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, opts)
}

// Serve is also usable by integration tests. The flock remains held for the
// process lifetime, including when ClickHouse is temporarily unavailable.
func Serve(ctx context.Context, o Options) error {
	if o.Interval <= 0 {
		return fmt.Errorf("metrics interval must be positive")
	}
	lock, err := acquireInstanceLock(o.LockFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := loadCheckpoint(o.Offsets); err != nil {
		return fmt.Errorf("invalid checkpoint: %w", err)
	}
	scraper, err := newMetricsWriter(o.MetricsURL, o.Instance, o.Interval)
	if err != nil {
		return err
	}
	db := clickhouse.New(o.ClickHouse, o.User, os.Getenv("CH_PASSWORD"))
	log.Printf("ingester started: events=%s alerts=%s offsets=%s", o.Events, o.Alerts, o.Offsets)
	for {
		if err := db.Init(ctx); err == nil {
			break
		} else if ctx.Err() != nil {
			return nil
		} else {
			log.Printf("ingester ClickHouse init: %v; retrying", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	// Event/alert import and metric snapshots have independent loops. A metrics
	// outage does not stop JSONL import; a JSONL error does not stop metrics.
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); ingest(ctx, db, o.Events, o.Alerts, o.Offsets) }()
	if scraper != nil {
		workers.Add(1)
		go func() { defer workers.Done(); scraper.run(ctx, db) }()
	}
	<-ctx.Done()
	workers.Wait() // finish in-flight checkpoint/HTTP cleanup before leaving
	log.Print("ingester stopping")
	return nil
}
