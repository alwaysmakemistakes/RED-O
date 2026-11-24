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
	"sort"
	"sync"
	"syscall"
	"time"

	"runtime-detector/internal/collector"
	"runtime-detector/internal/contextpolicy"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/exception"
	"runtime-detector/internal/heartbeat"
	"runtime-detector/internal/metrics"
	"runtime-detector/internal/model"
	"runtime-detector/internal/multisensor"
	"runtime-detector/internal/normalizer"
	"runtime-detector/internal/output"
	"runtime-detector/internal/storage"
)

func Run(args []string) {
	fs := flag.NewFlagSet("detector", flag.ExitOnError)
	source := fs.String("source", "jsonl", "source: jsonl, tetra or multi")
	sensors := fs.String("sensors", "", "multi-source sensor configuration JSON (required for -source multi)")
	sensorLateness := fs.Duration("sensor-lateness", 2*time.Second, "multi-source event-time reorder tolerance")
	sensorIdle := fs.Duration("sensor-idle-timeout", 4*time.Second, "exclude idle sensor from global watermark after duration")
	sensorBuffer := fs.Int("sensor-buffer", 8192, "maximum globally pending multi-sensor events")
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
	contextPolicyFlag := fs.String("context-policy", "", "optional context-aware triage policy JSON; annotates alerts without suppressing them")
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
	contextPolicyPath = *contextPolicyFlag
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
	sensorConfigPath = *sensors
	sensorLatenessDelay = *sensorLateness
	sensorIdleDuration = *sensorIdle
	sensorBufferLimit = *sensorBuffer
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runModeSourceFiltered(ctx, *source, *kubectl, *kubeNamespace, *eventNamespace, *input, *events, *raw, *rules, *correlations, *alerts, *mode, *socRaw, *socBuffer); err != nil {
		log.Fatal(err)
	}
}

var correlationDelay = 2 * time.Second
var correlationBufferLimit = 256
var exceptionPath string
var contextPolicyPath string
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
var sensorConfigPath string
var sensorLatenessDelay = 2 * time.Second
var sensorIdleDuration = 4 * time.Second
var sensorBufferLimit = 8192

func runMode(ctx context.Context, input, events, raw, rules, correlations, alerts, modeStr string, socRaw bool, socBuffer int) error {
	return runModeSource(ctx, "jsonl", "kubectl", "kube-system", input, events, raw, rules, correlations, alerts, modeStr, socRaw, socBuffer)
}

func runModeSource(ctx context.Context, source, kubectl, kubeNamespace, input, events, raw, rules, correlations, alerts, modeStr string, socRaw bool, socBuffer int) error {
	if source != "jsonl" && source != "tetra" && source != "multi" {
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
	var sensorCfg multisensor.Config
	var merger *multisensor.Merger
	if source == "multi" {
		if sensorConfigPath == "" {
			return errors.New("-source multi requires -sensors CONFIG.json")
		}
		sensorCfg, err = multisensor.Load(sensorConfigPath)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(sensorCfg.Sensors))
		for _, s := range sensorCfg.Sensors {
			ids = append(ids, s.ID)
		}
		merger, err = multisensor.NewMerger(ids, sensorLatenessDelay, sensorIdleDuration, sensorBufferLimit, time.Now())
		if err != nil {
			return err
		}
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
	if source == "multi" {
		paths = append(paths, sensorConfigPath)
		for _, s := range sensorCfg.Sensors {
			if s.Type == "jsonl" || s.Type == "audit" {
				paths = append(paths, s.Path)
			}
		}
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
	if (source == "tetra" || source == "multi") && heartbeatPath != "" {
		hb = heartbeat.New(heartbeatPath, source)
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

	var contextCfg *contextpolicy.Config
	if contextPolicyPath != "" {
		loaded, err := contextpolicy.Load(contextPolicyPath)
		if err != nil {
			return fmt.Errorf("context policy: %w", err)
		}
		contextCfg = &loaded
		log.Printf("context-aware triage enabled: %d policies (advisory only; raw alerts preserved)", len(loaded.Policies))
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
			// Derive alert provenance from *all* linked source events, not just
			// the terminal event. A chain may span sensors on the same cluster.
			origins := make(map[string]bool)
			cluster := ""
			for _, e := range related(a) {
				if e.Sensor == nil {
					continue
				}
				origins[e.Sensor.ID] = true
				if cluster == "" {
					cluster = e.Sensor.Cluster
				}
				if cluster != e.Sensor.Cluster {
					cluster = ""
					break
				}
			}
			if len(origins) > 0 {
				a.Cluster = cluster
				for id := range origins {
					a.SensorIDs = append(a.SensorIDs, id)
				}
				sort.Strings(a.SensorIDs)
			}
			if contextCfg != nil {
				evidence := related(a)
				assessment := contextCfg.Assess(a, evidence, len(evidence) == len(a.RelatedEventIDs) && len(a.RelatedEventIDs) > 0)
				a.Context = &assessment
			}
			if exceptionCache.SuppressedWithEvents(a, related(a)) {
				if registry != nil {
					registry.Suppressed()
				}
				continue
			}
			a.EmittedAt = time.Now().UTC().Format(time.RFC3339Nano)
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
	processNormalized := func(event model.SecurityEvent) error {
		if engine != nil {
			found, err := engine.Evaluate(event)
			if err != nil {
				return err
			}
			if err = writeAlerts(found); err != nil {
				return err
			}
		}
		if correlator != nil {
			found, err := correlator.Observe(event)
			if err != nil {
				return err
			}
			if err = writeAlerts(found); err != nil {
				return err
			}
			if registry != nil {
				st := correlator.Stats()
				registry.Correlation(st.Pending, st.LateDropped, st.ForcedReleased)
			}
		}
		return nil
	}
	handleWithOrigin := func(line []byte, origin *multisensor.Record) error {
		processingMu.Lock()
		began := time.Now()
		defer func() {
			if registry != nil {
				registry.Processing(time.Since(began))
			}
			processingMu.Unlock()
		}()
		if hb != nil {
			// Multi-mode aggregate heartbeat denotes receipt of telemetry;
			// per-sensor liveness is not guaranteed by this file.
			if source == "multi" && !hb.Snapshot().Connected {
				hb.Connected()
			}
			hb.Event()
		}
		if registry != nil && origin != nil {
			registry.SensorReceived(origin.Sensor.ID)
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
		rawRecord := line
		if origin != nil {
			// Preserve source attribution in forensic raw JSONL without
			// changing the underlying Tetragon/Audit payload structure.
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(line, &obj); err != nil {
				return err
			}
			provenance := model.Sensor{ID: origin.Sensor.ID, Type: origin.Sensor.Type, Cluster: origin.Sensor.Cluster, Node: origin.Sensor.Node}
			meta, _ := json.Marshal(provenance)
			at, _ := json.Marshal(origin.ReceivedAt.UTC().Format(time.RFC3339Nano))
			obj["_redo_origin"] = meta
			obj["_redo_received_at"] = at
			packed, err := json.Marshal(obj)
			if err != nil {
				return err
			}
			rawRecord = packed
		}
		if e := router.ObserveRaw(rawRecord); e != nil {
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
		if origin != nil {
			t, err := time.Parse(time.RFC3339Nano, event.Timestamp)
			if err != nil {
				return err
			}
			event.Timestamp = t.UTC().Format(time.RFC3339Nano)
			event.ReceivedAt = origin.ReceivedAt.UTC().Format(time.RFC3339Nano)
			event.Sensor = &model.Sensor{ID: origin.Sensor.ID, Type: origin.Sensor.Type, Cluster: origin.Sensor.Cluster, Node: origin.Sensor.Node}
			// Node from the event takes precedence, when present. The configured
			// node is a documented fallback, not an authenticated kernel fact.
			if event.Node == "" {
				event.Node = origin.Sensor.Node
			}
			if origin.Sensor.Node != "" && event.Node != origin.Sensor.Node {
				invalid++
				if registry != nil {
					registry.Invalid()
				}
				log.Printf("sensor %s node mismatch: expected %q got %q", origin.Sensor.ID, origin.Sensor.Node, event.Node)
				return nil
			}
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
		if merger != nil {
			ready, err := merger.Observe(origin.Sensor.ID, event, origin.ReceivedAt)
			if err != nil {
				return err
			}
			for _, ev := range ready {
				if err := processNormalized(ev); err != nil {
					return err
				}
			}
			return nil
		}
		return processNormalized(event)
	}
	handle := func(line []byte) error { return handleWithOrigin(line, nil) }
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
	if source == "multi" {
		log.Printf("starting %d independent sensors; event-time lateness=%s idle-timeout=%s", len(sensorCfg.Sensors), sensorLatenessDelay, sensorIdleDuration)
		err = multisensor.Run(ctx, sensorCfg, func(rec multisensor.Record) error {
			return handleWithOrigin(rec.Data, &rec)
		}, func(now time.Time) error {
			processingMu.Lock()
			defer processingMu.Unlock()
			for _, ev := range merger.Tick(now) {
				if e := processNormalized(ev); e != nil {
					return e
				}
			}
			if registry != nil {
				st := merger.Stats()
				registry.SensorMerge(st.Pending, st.Late, st.Forced, st.FutureSkew)
			}
			if correlator != nil {
				found, e := correlator.FlushIdle(now)
				if e != nil {
					return e
				}
				if e = writeAlerts(found); e != nil {
					return e
				}
			}
			return nil
		}, func(id string) error {
			processingMu.Lock()
			defer processingMu.Unlock()
			ready, e := merger.Finish(id, time.Now())
			if e != nil {
				return e
			}
			for _, ev := range ready {
				if e := processNormalized(ev); e != nil {
					return e
				}
			}
			return nil
		})
		processingMu.Lock()
		for _, ev := range merger.Flush() {
			if e := processNormalized(ev); e != nil && err == nil {
				err = e
			}
		}
		stats := merger.Stats()
		log.Printf("multi-sensor merge: pending=%d late=%d forced=%d", stats.Pending, stats.Late, stats.Forced)
		processingMu.Unlock()
	} else if source == "tetra" {
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
