package detectorapp

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"runtime-detector/internal/collector"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/exception"
	"runtime-detector/internal/heartbeat"
	"runtime-detector/internal/metrics"
	"runtime-detector/internal/model"
	"runtime-detector/internal/normalizer"
	"runtime-detector/internal/output"
	"runtime-detector/internal/storage"
)

func Run(args []string) {
	fs := flag.NewFlagSet("detector", flag.ExitOnError)
	source := fs.String("source", "jsonl", "source: jsonl or tetra")
	kubeNamespace := fs.String("tetragon-namespace", "kube-system", "Tetragon pod namespace")
	eventNamespace := fs.String("event-namespace", "", "optional Tetragon event namespace filter (tetra source only)")
	kubectl := fs.String("kubectl", "kubectl", "kubectl binary path")
	input := fs.String("input", "-", "Tetragon JSONL source file, or - for stdin")
	events := fs.String("events", "data/events.jsonl", "normalized JSONL output (append)")
	raw := fs.String("raw", "", "optional raw JSONL output (append); empty disables")
	rules := fs.String("rules", "", "optional detection rules config; empty disables detection")
	correlations := fs.String("correlations", "", "optional correlation rule config (JSON)")
	correlationBuffer := fs.Int("correlation-buffer", 256, "max pending correlation events per container")
	correlationLateness := fs.Duration("correlation-lateness", 2*time.Second, "allowed out-of-order delay for correlation; 0 disables buffering")
	alerts := fs.String("alerts", "data/alerts.jsonl", "security alerts JSONL output (append)")
	mode := fs.String("mode", "forensic", "output mode: forensic, soc, lightweight")
	socRaw := fs.Bool("soc-raw", false, "SOC also exports raw events")
	socBuffer := fs.Int("soc-buffer", 10000, "SOC maximum cached normalized events")
	exceptions := fs.String("exceptions", "", "optional dynamic exception JSON file")
	heartbeatFile := fs.String("heartbeat", "", "optional collector heartbeat JSON output, updated every 5 seconds")
	metricsAddr := fs.String("metrics-listen", "", "optional Prometheus metrics listener, e.g. 127.0.0.1:9095 (loopback only)")
	gapLog := fs.String("gap-log", "", "optional JSONL log of completed collector disconnect intervals")
	maxLogSize := fs.Int64("storage-max-bytes", 64<<20, "rotate JSONL outputs above this size (0 disables)")
	maxLogSegments := fs.Int("storage-max-segments", 32, "maximum immutable segments for events/alerts; fail closed if exceeded")
	rawRetentionFlag := fs.Duration("raw-retention", 24*time.Hour, "retain closed raw segments for this duration (0 disables age deletion)")
	rawMaxStorageFlag := fs.Int64("raw-max-storage", 2<<30, "raw active file + archived segments byte budget; oldest closed segments deleted first")
	rawMaxSegmentsFlag := fs.Int("raw-max-segments", 32, "maximum closed raw segments; oldest segments deleted first")
	auditFileFlag := fs.String("audit-file", "", "optional Kubernetes API audit JSONL file, followed alongside Tetragon stream")
	auditFromStartFlag := fs.Bool("audit-from-start", false, "read existing audit records from beginning (otherwise start at EOF)")
	fs.Parse(args)
	correlationDelay = *correlationLateness
	correlationBufferLimit = *correlationBuffer
	exceptionPath = *exceptions
	heartbeatPath = *heartbeatFile
	gapLogPath = *gapLog
	metricsListen = *metricsAddr
	storageMaxBytes = *maxLogSize
	storageMaxSegments = *maxLogSegments
	rawRetention = *rawRetentionFlag
	rawMaxStorage = *rawMaxStorageFlag
	rawMaxSegments = *rawMaxSegmentsFlag
	auditFilePath = *auditFileFlag
	auditFromStart = *auditFromStartFlag
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runModeSourceFiltered(ctx, *source, *kubectl, *kubeNamespace, *eventNamespace, *input, *events, *raw, *rules, *correlations, *alerts, *mode, *socRaw, *socBuffer); err != nil {
		log.Fatal(err)
	}
}

var correlationDelay = 2 * time.Second
var correlationBufferLimit = 256
var exceptionPath string
var heartbeatPath string
var gapLogPath string
var metricsListen string
var storageMaxBytes int64 = 64 << 20
var storageMaxSegments int = 32
var rawRetention = 24 * time.Hour
var rawMaxStorage int64 = 2 << 30
var rawMaxSegments = 32
var auditFilePath string
var auditFromStart bool

func runMode(ctx context.Context, input, events, raw, rules, correlations, alerts, modeStr string, socRaw bool, socBuffer int) error {
	return runModeSource(ctx, "jsonl", "kubectl", "kube-system", input, events, raw, rules, correlations, alerts, modeStr, socRaw, socBuffer)
}

func runModeSource(ctx context.Context, source, kubectl, kubeNamespace, input, events, raw, rules, correlations, alerts, modeStr string, socRaw bool, socBuffer int) error {
	if source != "jsonl" && source != "tetra" {
		return fmt.Errorf("invalid source %q", source)
	}
	return runModeSourceFiltered(ctx, source, kubectl, kubeNamespace, "", input, events, raw, rules, correlations, alerts, modeStr, socRaw, socBuffer)
}

func runModeSourceFiltered(ctx context.Context, source, kubectl, kubeNamespace, eventNamespace, input, events, raw, rules, correlations, alerts, modeStr string, socRaw bool, socBuffer int) error {
	mode, err := output.ParseMode(modeStr)
	if err != nil {
		return err
	}
	if rules == "" && correlations == "" {
		return errors.New("at least one of -rules or -correlations required to generate alerts")
	}
	if raw == "" && (mode == output.Forensic || mode == output.SOC && socRaw) {
		raw = "data/raw.jsonl"
	}
	paths := []string{alerts}
	if source == "jsonl" {
		paths = append(paths, input)
	}
	if mode != output.Lightweight {
		paths = append(paths, events)
	}
	if mode == output.Forensic || mode == output.SOC && socRaw {
		paths = append(paths, raw)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "-" {
			continue
		}
		clean, _ := filepath.Abs(p)
		if seen[clean] {
			return fmt.Errorf("input/output paths collide: %s", p)
		}
		seen[clean] = true
	}
	var reader io.Reader = os.Stdin
	if source == "jsonl" && input != "-" {
		f, e := os.Open(input)
		if e != nil {
			return e
		}
		defer f.Close()
		reader = f
	}
	alertsFile, err := storage.Open(alerts, storageMaxBytes, storageMaxSegments)
	if err != nil {
		return err
	}
	defer alertsFile.Close()
	var eventsFile, rawFile *storage.Writer
	if mode != output.Lightweight {
		eventsFile, err = storage.Open(events, storageMaxBytes, storageMaxSegments)
		if err != nil {
			return err
		}
		defer eventsFile.Close()
	}
	if mode == output.Forensic || mode == output.SOC && socRaw {
		rawFile, err = storage.OpenRaw(raw, storageMaxBytes, rawMaxSegments, rawRetention, rawMaxStorage)
		if err != nil {
			return err
		}
		defer rawFile.Close()
	}
	router, err := output.NewRouter(mode, rawFile, eventsFile, alertsFile, socRaw, socBuffer)
	if err != nil {
		return err
	}
	var correlator *correlation.Correlator
	if correlations != "" {
		cfg, e := correlation.Load(correlations)
		if e != nil {
			return e
		}
		correlator, e = correlation.NewWithLateness(cfg, correlationDelay)
		if e != nil {
			return e
		}
		if e = correlator.SetBufferLimit(correlationBufferLimit); e != nil {
			return e
		}
	}
	var engine *detection.Engine
	if rules != "" {
		cfg, e := detection.Load(rules)
		if e != nil {
			return e
		}
		engine, e = detection.New(cfg)
		if e != nil {
			return e
		}
	}
	var total, normalized, skipped, invalid, detected int
	var registry *metrics.Registry
	if metricsListen != "" {
		host, _, splitErr := net.SplitHostPort(metricsListen)
		if splitErr != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			return fmt.Errorf("-metrics-listen must use a loopback host:port")
		}
		registry = metrics.New()
		listener, listenErr := net.Listen("tcp", metricsListen)
		if listenErr != nil {
			return fmt.Errorf("metrics listen: %w", listenErr)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", registry)
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if e := server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Printf("metrics server: %v", e)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
	}
	var hb *heartbeat.Reporter
	if source == "tetra" && heartbeatPath != "" {
		hb = heartbeat.New(heartbeatPath, "tetra")
		if e := hb.Write(); e != nil {
			return fmt.Errorf("initial heartbeat: %w", e)
		}
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-ticker.C:
					if e := hb.Write(); e != nil {
						log.Printf("heartbeat write error: %v", e)
					}
				}
			}
		}()
		defer func() {
			hb.Stop()
			if e := hb.Write(); e != nil {
				log.Printf("final heartbeat: %v", e)
			}
		}()
	}

	exceptionCache := exception.NewCache(exceptionPath)
	recent := map[string]model.SecurityEvent{}
	order := []string{}
	related := func(a model.SecurityAlert) []model.SecurityEvent {
		out := []model.SecurityEvent{}
		for _, id := range a.RelatedEventIDs {
			if ev, ok := recent[id]; ok {
				out = append(out, ev)
			}
		}
		return out
	}
	var processingMu sync.Mutex
	writeAlerts := func(found []model.SecurityAlert) error {
		for _, a := range found {
			if exceptionCache.SuppressedWithEvents(a, related(a)) {
				if registry != nil {
					registry.Suppressed()
				}
				continue
			}
			if err := router.ObserveAlert(a); err != nil {
				return err
			}
			detected++
			if registry != nil {
				registry.Alert(a.Timestamp)
			}
		}
		return nil
	}
	handle := func(line []byte) error {
		processingMu.Lock()
		began := time.Now()
		defer func() {
			if registry != nil {
				registry.Processing(time.Since(began))
			}
			processingMu.Unlock()
		}()
		if hb != nil {
			hb.Event()
		}
		total++
		if registry != nil {
			registry.Received()
		}
		if !jsonValid(line) {
			invalid++
			if registry != nil {
				registry.Invalid()
			}
			log.Printf("invalid JSON at record %d", total)
			return nil
		}
		if e := router.ObserveRaw(line); e != nil {
			return e
		}
		event, e := normalizer.Normalize(line)
		if errors.Is(e, normalizer.ErrUnsupportedEvent) {
			skipped++
			if registry != nil {
				registry.Unsupported()
			}
			return nil
		}
		if e != nil {
			invalid++
			if registry != nil {
				registry.Invalid()
			}
			log.Printf("invalid Tetragon event at record %d: %v", total, e)
			return nil
		}
		if e = router.ObserveEvent(event); e != nil {
			return e
		}
		normalized++
		if registry != nil {
			registry.Normalized()
		}
		recent[event.EventID] = event
		order = append(order, event.EventID)
		if len(order) > 10000 {
			delete(recent, order[0])
			order = order[1:]
		}
		if engine != nil {
			found, e := engine.Evaluate(event)
			if e != nil {
				return e
			}
			if e = writeAlerts(found); e != nil {
				return e
			}
		}
		if correlator != nil {
			found, e := correlator.Observe(event)
			if e != nil {
				return e
			}
			if e = writeAlerts(found); e != nil {
				return e
			}
			if registry != nil {
				st := correlator.Stats()
				registry.Correlation(st.Pending, st.LateDropped, st.ForcedReleased)
			}
		}
		return nil
	}
	// Flush idle event-time buffers on live sources: quiet containers must not
	// wait indefinitely for another event to emit their final alert.
	var tickerDone chan struct{}
	var tickerWG sync.WaitGroup
	if source == "tetra" && correlator != nil && correlationDelay > 0 {
		tickerDone = make(chan struct{})
		tickerWG.Add(1)
		go func() {
			defer tickerWG.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-tickerDone:
					return
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					processingMu.Lock()
					found, flushErr := correlator.FlushIdle(now)
					if flushErr == nil {
						flushErr = writeAlerts(found)
					}
					if registry != nil {
						st := correlator.Stats()
						registry.Correlation(st.Pending, st.LateDropped, st.ForcedReleased)
					}
					processingMu.Unlock()
					if flushErr != nil {
						log.Printf("correlation idle flush error: %v", flushErr)
					}
				}
			}
		}()
	}
	var auditWG sync.WaitGroup
	auditCtx, auditCancel := context.WithCancel(ctx)
	defer auditCancel()
	if source == "tetra" && auditFilePath != "" {
		// Validate access before announcing a running detector. The follower
		// runs through the same serialized handler as the Tetragon stream.
		if f, e := os.Open(auditFilePath); e != nil {
			return fmt.Errorf("audit-file: %w", e)
		} else {
			_ = f.Close()
		}
		auditWG.Add(1)
		go func() {
			defer auditWG.Done()
			log.Printf("following Kubernetes audit log %s (from-start=%v)", auditFilePath, auditFromStart)
			if e := collector.FollowAuditFile(auditCtx, auditFilePath, auditFromStart, handle); e != nil && ctx.Err() == nil {
				log.Printf("Kubernetes audit follower stopped: %v", e)
			}
		}()
	}
	if source == "tetra" {
		log.Printf("starting continuous tetra stream; kube namespace=%s", kubeNamespace)
		err = collector.StreamTetra(ctx, collector.TetraConfig{Kubectl: kubectl, Namespace: kubeNamespace, DaemonSet: "tetragon", Container: "tetragon", FilterNamespace: eventNamespace, MinBackoff: time.Second, MaxBackoff: 30 * time.Second, OnConnect: func() {
			if hb != nil {
				gap := hb.Connected()
				if gap != nil {
					if writeErr := heartbeat.AppendGap(gapLogPath, *gap); writeErr != nil {
						log.Printf("collector gap journal write error: %v", writeErr)
					}
					log.Printf("collector stream recovered: gap=%dms (possible event loss; count unknown)", gap.DurationMilliseconds)
				}
				_ = hb.Write()
			}
			log.Print("tetra stream connected")
		}, OnDisconnect: func(e error) {
			if hb != nil {
				hb.Disconnected(e)
				_ = hb.Write()
			}
			log.Printf("tetra stream disconnected: %v; reconnecting", e)
		}}, handle)
	} else {
		err = collector.ReadJSONL(ctx, reader, handle)
	}
	// Close the follower and wait for its serialized handler to finish before
	// flushing output files, including on Tetragon processing errors.
	auditCancel()
	auditWG.Wait()
	if tickerDone != nil {
		close(tickerDone)
		tickerWG.Wait()
	}
	if correlator != nil {
		processingMu.Lock()
		found, flushErr := correlator.Flush()
		if flushErr == nil {
			flushErr = writeAlerts(found)
		}
		stats := correlator.Stats()
		if registry != nil {
			registry.Correlation(stats.Pending, stats.LateDropped, stats.ForcedReleased)
		}
		processingMu.Unlock()
		if flushErr != nil {
			return fmt.Errorf("correlation final flush: %w", flushErr)
		}
		log.Printf("correlation: lateness=%s pending=%d late_dropped=%d forced_released=%d", correlationDelay, stats.Pending, stats.LateDropped, stats.ForcedReleased)
	}
	log.Printf("mode=%s processed=%d normalized=%d unsupported=%d invalid=%d alerts=%d", mode, total, normalized, skipped, invalid, detected)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if invalid > 0 {
		return fmt.Errorf("%d invalid record(s) encountered", invalid)
	}
	return nil
}

func openAppend(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}

func jsonValid(line []byte) bool { return json.Valid(line) }
