package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime-detector/internal/clickhouse"
	"runtime-detector/internal/exception"
	"runtime-detector/internal/heartbeat"
	"runtime-detector/internal/model"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type app struct {
	db                       *clickhouse.Client
	storage                  string
	localEvents, localAlerts string
	exceptionFile, token     string
	page                     *template.Template
	kubeNamespace            string
	heartbeatFile            string
	healthMu                 sync.Mutex
	healthCache              []agentHealth
	healthAt                 time.Time
}

func Run(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:8088", "bind address; default localhost")
	storage := fs.String("storage", "clickhouse", "query backend: clickhouse or jsonl (recent local data)")
	localEvents := fs.String("local-events", "data/live-events.jsonl", "local events in jsonl mode")
	localAlerts := fs.String("local-alerts", "data/live-alerts.jsonl", "local alerts in jsonl mode")
	ch := fs.String("clickhouse", "http://127.0.0.1:8123", "ClickHouse URL")
	user := fs.String("ch-user", "default", "ClickHouse user")
	legacyEvents := fs.String("events", "", "deprecated: configure -events on Ingester instead")
	legacyAlerts := fs.String("alerts", "", "deprecated: configure -alerts on Ingester instead")
	legacyOffsets := fs.String("offsets", "", "deprecated: configure -offsets on Ingester instead")
	exceptions := fs.String("exceptions", "data/exceptions.json", "shared exceptions path")
	kubeNamespace := fs.String("kube-namespace", "kube-system", "namespace of Tetragon DaemonSet")
	heartbeatFile := fs.String("heartbeat", "", "optional shared collector heartbeat JSON path")
	detectorMetrics := fs.String("detector-metrics", "http://127.0.0.1:9095/metrics", "local detector Prometheus endpoint; empty disables metrics dashboard")
	fs.Parse(args)
	if *storage != "clickhouse" && *storage != "jsonl" {
		log.Fatal("web storage must be clickhouse or jsonl")
	}
	if *legacyEvents != "" || *legacyAlerts != "" || *legacyOffsets != "" {
		log.Print("Web no longer imports JSONL: -events/-alerts/-offsets are ignored; configure RED-O Ingester instead")
	}
	token := os.Getenv("WEB_PASSWORD")
	if token == "" {
		log.Fatal("WEB_PASSWORD must be set (use a strong secret)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db := clickhouse.New(*ch, *user, os.Getenv("CH_PASSWORD"))
	// The Ingester owns schema creation and inserts; Web must remain read-only.
	// It can start while ClickHouse is unavailable, serving errors until recovery.
	monitor, err := newMetricsMonitor(*detectorMetrics)
	if err != nil {
		log.Fatal(err)
	}
	if monitor != nil {
		monitor.db = db
		monitor.instance = "detector-local"
		go monitor.run(ctx) // read-only liveness cache; no ClickHouse writes
	}
	a := &app{db: db, storage: *storage, localEvents: *localEvents, localAlerts: *localAlerts, exceptionFile: *exceptions, token: token, page: template.Must(template.New("page").Parse(pageHTML)), kubeNamespace: *kubeNamespace, heartbeatFile: *heartbeatFile}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/alert/", a.alertPage)
	mux.HandleFunc("/exception/new", a.exceptionPage)
	mux.HandleFunc("/api/alerts", a.alerts)
	mux.HandleFunc("/api/events", a.events)
	mux.HandleFunc("/api/agents", a.agents)
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if monitor == nil {
			http.Error(w, "Metrics are disabled", 503)
			return
		}
		monitor.serve(w, r)
	})
	mux.HandleFunc("/api/alerts/", a.detail)
	mux.HandleFunc("/api/exceptions", a.exceptions)
	mux.HandleFunc("/api/exceptions/", a.exceptionByID)
	srv := &http.Server{Addr: *addr, Handler: a.auth(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(closeCtx)
	}()
	log.Printf("web listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
func (a *app) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		u, p, ok := r.BasicAuth()
		if !ok || u != os.Getenv("WEB_USER") || p != a.token || u == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Runtime Security Console"`)
			http.Error(w, "Unauthorized", 401)
			return
		}
		if r.Method != "GET" {
			origin := r.Header.Get("Origin")
			if origin != "" && origin != "http://"+r.Host && origin != "https://"+r.Host {
				http.Error(w, "Cross-origin modifications are disabled", 403)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" && r.Method == "POST" {
				http.Error(w, "application/json required", 415)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func write(w http.ResponseWriter, x any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(x)
}
func bad(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusBadRequest) }
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = a.page.Execute(w, nil)
}
func (a *app) alertPage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/alert/")
	if id == "" || len(id) > 128 || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = a.page.Execute(w, nil)
}
func sortClause(r *http.Request, alerts bool) string {
	allowed := map[string]string{"timestamp": "timestamp", "namespace": "namespace", "pod": "pod"}
	if alerts {
		allowed["rule_id"] = "rule_id"
		allowed["severity"] = "severity"
	} else {
		allowed["event_type"] = "event_type"
		allowed["process"] = "process_binary"
		allowed["file_path"] = "file_path"
		allowed["destination_ip"] = "destination_ip"
	}
	col := allowed[r.URL.Query().Get("sort")]
	if col == "" {
		col = "timestamp"
	}
	dir := " DESC"
	if r.URL.Query().Get("dir") == "asc" {
		dir = " ASC"
	}
	return " ORDER BY " + col + dir + ", timestamp DESC "
}
func (a *app) exceptionPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = a.page.Execute(w, nil)
}
func safeLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n < 1 {
		return 100
	}
	if n > 500 {
		return 500
	}
	return n
}
func (a *app) alerts(w http.ResponseWriter, r *http.Request) {
	if a.storage == "jsonl" {
		localList(w, r, a.localAlerts, true)
		return
	}
	q := `SELECT payload FROM runtime_security.alerts FINAL WHERE ({rule:String}='' OR rule_id={rule:String}) AND ({namespace:String}='' OR namespace={namespace:String}) AND ({severity:String}='' OR severity={severity:String}) AND ({search:String}='' OR positionCaseInsensitive(pod,{search:String})>0 OR positionCaseInsensitive(rule_id,{search:String})>0 OR positionCaseInsensitive(payload,{search:String})>0) ` + sortClause(r, true) + ` LIMIT {limit:UInt32} FORMAT JSONEachRow`
	rows, err := a.db.Query(r.Context(), q, map[string]string{"rule": r.URL.Query().Get("rule"), "namespace": r.URL.Query().Get("namespace"), "severity": r.URL.Query().Get("severity"), "search": r.URL.Query().Get("q"), "limit": strconv.Itoa(safeLimit(r))})
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writePayloads(w, rows)
}
func (a *app) events(w http.ResponseWriter, r *http.Request) {
	if a.storage == "jsonl" {
		localList(w, r, a.localEvents, false)
		return
	}
	q := `SELECT payload FROM runtime_security.events FINAL WHERE ({event_type:String}='' OR event_type={event_type:String}) AND ({namespace:String}='' OR namespace={namespace:String}) AND ({search:String}='' OR positionCaseInsensitive(pod,{search:String})>0 OR positionCaseInsensitive(process_binary,{search:String})>0 OR positionCaseInsensitive(file_path,{search:String})>0 OR positionCaseInsensitive(destination_ip,{search:String})>0 OR positionCaseInsensitive(event_type,{search:String})>0 OR positionCaseInsensitive(payload,{search:String})>0) ` + sortClause(r, false) + ` LIMIT {limit:UInt32} FORMAT JSONEachRow`
	rows, err := a.db.Query(r.Context(), q, map[string]string{"event_type": r.URL.Query().Get("type"), "namespace": r.URL.Query().Get("namespace"), "search": r.URL.Query().Get("q"), "limit": strconv.Itoa(safeLimit(r))})
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writePayloads(w, rows)
}

// Agents combine live Kubernetes readiness with historical ClickHouse telemetry.
func (a *app) agents(w http.ResponseWriter, r *http.Request) {
	if a.storage == "jsonl" {
		localAgents(w, r, a.localEvents)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	rows, err := a.db.Query(r.Context(), `SELECT JSONExtractString(payload, 'node') AS node, count() AS events, max(timestamp) AS last_seen, uniqExact(namespace) AS namespaces, uniqExact(pod) AS pods FROM runtime_security.events FINAL WHERE JSONExtractString(payload, 'node') != '' GROUP BY node ORDER BY last_seen DESC LIMIT 500 FORMAT JSONEachRow`, nil)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	a.healthMu.Lock()
	if time.Since(a.healthAt) >= 10*time.Second || a.healthAt.IsZero() {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		live, e := getAgentHealth(ctx, kubectlReader, a.kubeNamespace)
		cancel()
		if e != nil {
			a.healthMu.Unlock()
			write(w, map[string]any{"health_available": false, "error": e.Error(), "agents": rows, "checked_at": time.Now().UTC().Format(time.RFC3339)})
			return
		}
		a.healthCache = live
		a.healthAt = time.Now()
	}
	live := append([]agentHealth(nil), a.healthCache...)
	checkedAt := a.healthAt
	a.healthMu.Unlock()
	indexed := map[string]map[string]any{}
	for _, row := range rows {
		node, _ := row["node"].(string)
		indexed[node] = row
	}
	agents := []map[string]any{}
	for _, agent := range live {
		record := map[string]any{"node": agent.Node, "pod": agent.Pod, "phase": agent.Phase, "ready": agent.Ready, "node_ready": agent.NodeReady, "container_ready": agent.ContainerReady, "restarts": agent.Restarts, "started_at": agent.StartedAt, "status": agent.Status, "detail": agent.Detail, "events": 0, "last_seen": "", "namespaces": 0, "pods": 0}
		if t, ok := indexed[agent.Node]; ok {
			for _, key := range []string{"events", "last_seen", "namespaces", "pods"} {
				record[key] = t[key]
			}
			delete(indexed, agent.Node)
		}
		// Collector heartbeat is host-local (single collector deployment).
		if a.heartbeatFile != "" && agent.Node != "" {
			record["collector"] = collectorHealth(a.heartbeatFile, agent.Node)
		}
		agents = append(agents, record)
	}
	for _, record := range indexed {
		record["status"] = "not_observed_live"
		record["detail"] = "Stored telemetry only; no matching live Node"
		agents = append(agents, record)
	}
	write(w, map[string]any{"health_available": true, "agents": agents, "checked_at": checkedAt.UTC().Format(time.RFC3339)})
}
func writePayloads(w http.ResponseWriter, rows []map[string]any) {
	out := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		if s, ok := row["payload"].(string); ok && json.Valid([]byte(s)) {
			out = append(out, json.RawMessage(s))
		}
	}
	write(w, out)
}
func (a *app) detail(w http.ResponseWriter, r *http.Request) {
	if a.storage == "jsonl" {
		localDetail(w, r, a.localAlerts, a.localEvents)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if len(id) > 128 || id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	rows, err := a.db.Query(r.Context(), `SELECT payload FROM runtime_security.alerts FINAL WHERE alert_id={id:String} LIMIT 1 FORMAT JSONEachRow`, map[string]string{"id": id})
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	if len(rows) == 0 {
		http.NotFound(w, r)
		return
	}
	var alert map[string]any
	if err = json.Unmarshal([]byte(rows[0]["payload"].(string)), &alert); err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	related := []json.RawMessage{}
	if ids, ok := alert["related_event_ids"].([]any); ok {
		for _, v := range ids {
			eid, ok := v.(string)
			if !ok {
				continue
			}
			results, err := a.db.Query(r.Context(), `SELECT payload FROM runtime_security.events FINAL WHERE event_id={id:String} LIMIT 1 FORMAT JSONEachRow`, map[string]string{"id": eid})
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			if len(results) > 0 {
				related = append(related, json.RawMessage(results[0]["payload"].(string)))
			}
		}
	}
	write(w, map[string]any{"alert": alert, "events": related})
}
func (a *app) exceptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		entries, err := exception.Read(a.exceptionFile)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		write(w, entries)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var e exception.Entry
	d := json.NewDecoder(io.LimitReader(r.Body, 8192))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		bad(w, err)
		return
	}
	// Field-scoped exceptions must be tied to an existing alert and an
	// actual value present in one of its referenced events.
	if a.storage == "jsonl" {
		http.Error(w, "Creating exceptions requires ClickHouse mode; use exception file management", 503)
		return
	}
	if e.Field == "" || !exception.AllowedField(e.Field) {
		bad(w, fmt.Errorf("choose an event field"))
		return
	}
	alertID := r.URL.Query().Get("alert_id")
	if alertID == "" {
		bad(w, fmt.Errorf("alert_id required"))
		return
	}
	alerts, err := a.db.Query(r.Context(), `SELECT payload FROM runtime_security.alerts FINAL WHERE alert_id={id:String} LIMIT 1 FORMAT JSONEachRow`, map[string]string{"id": alertID})
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	if len(alerts) == 0 {
		http.Error(w, "alert not found", 404)
		return
	}
	var source struct {
		RuleID     string `json:"rule_id"`
		Kubernetes *struct {
			Namespace string `json:"namespace"`
			Pod       string `json:"pod"`
		} `json:"kubernetes"`
		RelatedEventIDs []string `json:"related_event_ids"`
	}
	if err := json.Unmarshal([]byte(alerts[0]["payload"].(string)), &source); err != nil {
		bad(w, err)
		return
	}
	if source.Kubernetes == nil || e.RuleID != source.RuleID || e.Namespace != source.Kubernetes.Namespace || (e.Pod != "" && e.Pod != source.Kubernetes.Pod) {
		bad(w, fmt.Errorf("rule/namespace/pod mismatch"))
		return
	}
	valueExists := false
	for _, id := range source.RelatedEventIDs {
		rows, er := a.db.Query(r.Context(), `SELECT payload FROM runtime_security.events FINAL WHERE event_id={id:String} LIMIT 1 FORMAT JSONEachRow`, map[string]string{"id": id})
		if er != nil {
			http.Error(w, er.Error(), 502)
			return
		}
		if len(rows) == 0 {
			continue
		}
		var ev model.SecurityEvent
		if json.Unmarshal([]byte(rows[0]["payload"].(string)), &ev) == nil && exception.EventField(ev, e.Field) == e.Value {
			valueExists = true
			break
		}
	}
	if !valueExists {
		bad(w, fmt.Errorf("field/value not found in related events"))
		return
	}
	e.ID = fmt.Sprintf("exc-%d", time.Now().UnixNano())
	e.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	e.Enabled = true
	if err := e.Valid(); err != nil {
		bad(w, err)
		return
	}
	entries, err := exception.Read(a.exceptionFile)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	entries = append(entries, e)
	if err := exception.Write(a.exceptionFile, entries); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	write(w, e)
}
func (a *app) exceptionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/exceptions/")
	entries, err := exception.Read(a.exceptionFile)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	updated := make([]exception.Entry, 0, len(entries))
	for _, e := range entries {
		if e.ID != id {
			updated = append(updated, e)
		}
	}
	if err := exception.Write(a.exceptionFile, updated); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	write(w, map[string]bool{"ok": true})
}

// collectorHealth intentionally distinguishes missing/stale heartbeat from an
// observed disconnection and never maps quiet event traffic to offline.
func collectorHealth(path, node string) map[string]any {
	s, err := heartbeat.Read(path)
	if err != nil {
		return map[string]any{"status": "unknown", "detail": "heartbeat unavailable: " + err.Error()}
	}
	if s.Node != "" && s.Node != node {
		return map[string]any{"status": "unknown", "detail": "collector reports another node: " + s.Node}
	}
	age := time.Since(s.UpdatedAt)
	status := "connected"
	if age < 0 || age > 20*time.Second {
		status = "stale"
	} else if !s.Connected {
		status = "disconnected"
	}
	return map[string]any{"status": status, "updated_at": s.UpdatedAt, "started_at": s.StartedAt, "last_event_at": s.LastEventAt, "last_connected_at": s.LastConnectedAt, "last_disconnected_at": s.LastDisconnectedAt, "events_received": s.EventsReceived, "reconnects": s.Reconnects, "last_error": s.LastError, "age_seconds": int(age.Seconds())}
}
