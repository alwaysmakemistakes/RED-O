// Package quality evaluates detection rules against explicitly labelled trials.
// Fixture scores describe a deterministic synthetic laboratory dataset ONLY.
// Real trials require provenance-checked event IDs and independently assigned labels.
package quality

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/model"
)

type Suite struct {
	SchemaVersion string     `json:"schema_version"`
	Scenarios     []Scenario `json:"scenarios"`
}
type Scenario struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	TargetRules []string `json:"target_rules"`
	Cases       []Case   `json:"cases"`
}
type Case struct {
	ID        string                `json:"id"`
	Label     string                `json:"label"`
	Rationale string                `json:"rationale"`
	Events    []model.SecurityEvent `json:"events"`
}
type Trial struct {
	ID       string   `json:"id"`
	Scenario string   `json:"scenario"`
	Label    string   `json:"label"`
	EventIDs []string `json:"event_ids"`
	// v1.1: independently recorded action evidence; do not infer execution from alerts.
	ActionID         string `json:"action_id,omitempty"`
	ActionStatus     string `json:"action_status,omitempty"` // completed or failed
	ActionStartedAt  string `json:"action_started_at,omitempty"`
	ActionFinishedAt string `json:"action_finished_at,omitempty"`
	PodUID           string `json:"pod_uid,omitempty"`
	ExpectedEvents   int    `json:"expected_events,omitempty"` // minimum independent evidence records expected
}
type Manifest struct {
	SchemaVersion string  `json:"schema_version"`
	Trials        []Trial `json:"trials"`
}

type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

// Coverage is separate from detection performance and never treats absent
// telemetry for a negative action as a true negative.
type Coverage struct {
	Actions  int      `json:"actions"`
	Observed int      `json:"observed"`
	Missing  int      `json:"missing"`
	Partial  int      `json:"partial"`
	Rate     *float64 `json:"rate,omitempty"`
}

type LatencySummary struct {
	Samples int      `json:"samples"`
	P50Ms   *float64 `json:"p50_ms,omitempty"`
	P95Ms   *float64 `json:"p95_ms,omitempty"`
	P99Ms   *float64 `json:"p99_ms,omitempty"`
}

func (c *Counts) Add(v Counts) { c.TP += v.TP; c.FP += v.FP; c.FN += v.FN; c.TN += v.TN }
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

type TrialResult struct {
	TrialID             string   `json:"trial_id"`
	Scenario            string   `json:"scenario"`
	Label               string   `json:"label"`
	Repeat              int      `json:"repeat"`
	Confusion           string   `json:"confusion"`
	TargetRules         []string `json:"target_rules"`
	ObservedTargetRules []string `json:"observed_target_rules"`
	OtherObservedRules  []string `json:"other_observed_rules"`
	SourceEventIDs      []string `json:"source_event_ids,omitempty"`
	TelemetryStatus     string   `json:"telemetry_status,omitempty"` // observed, missing, partial, synthetic
	MissingEventIDs     []string `json:"missing_event_ids,omitempty"`
	ExpectedEvents      int      `json:"expected_events,omitempty"`
	ObservedEvents      int      `json:"observed_events,omitempty"`
	ActionID            string   `json:"action_id,omitempty"`
	ActionStartedAt     string   `json:"action_started_at,omitempty"`
	FirstAlertEmittedAt string   `json:"first_target_alert_emitted_at,omitempty"`
	LatencyMs           *float64 `json:"latency_ms,omitempty"` // action start to first target output attempt
	EventToDetectionMs  *float64 `json:"event_to_detection_ms,omitempty"`
}
type ScenarioResult struct {
	Evaluated        bool     `json:"evaluated"`
	PrecisionDefined bool     `json:"precision_defined"`
	RecallDefined    bool     `json:"recall_defined"`
	F1Defined        bool     `json:"f1_defined"`
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	TargetRules      []string `json:"target_rules"`
	Counts
	Coverage       Coverage       `json:"coverage"`
	EndToEndRecall *float64       `json:"end_to_end_recall,omitempty"`
	Latency        LatencySummary `json:"latency"`
	Precision      float64        `json:"precision"`
	Recall         float64        `json:"recall"`
	F1             float64        `json:"f1"`
}
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Kind          string            `json:"kind"`
	GeneratedAt   string            `json:"generated_at_utc"`
	SuiteFile     string            `json:"suite_file"`
	InputSHA256   map[string]string `json:"input_sha256,omitempty"`
	Runs          int               `json:"runs"`
	Counts
	Coverage         Coverage         `json:"coverage"`
	EndToEnd         Counts           `json:"end_to_end_counts"`
	EndToEndRecall   *float64         `json:"end_to_end_recall,omitempty"`
	Latency          LatencySummary   `json:"latency"`
	Precision        float64          `json:"precision"`
	Recall           float64          `json:"recall"`
	F1               float64          `json:"f1"`
	ByScenario       []ScenarioResult `json:"by_scenario"`
	PrecisionDefined bool             `json:"precision_defined"`
	RecallDefined    bool             `json:"recall_defined"`
	F1Defined        bool             `json:"f1_defined"`
	Trials           []TrialResult    `json:"trials"`
	Caveats          []string         `json:"caveats"`
}

func loadSuite(path string, rc detection.Config, cc correlation.Config) (Suite, error) {
	var suite Suite
	b, e := os.ReadFile(path)
	if e != nil {
		return suite, e
	}
	if e = json.Unmarshal(b, &suite); e != nil {
		return suite, fmt.Errorf("suite: %w", e)
	}
	if suite.SchemaVersion != "1.0" || len(suite.Scenarios) != 7 {
		return suite, fmt.Errorf("suite requires schema_version 1.0 and exactly seven scenarios")
	}
	active := map[string]bool{}
	for _, r := range rc.Rules {
		if r.Enabled {
			active[r.ID] = true
		}
	}
	for _, r := range cc.Rules {
		if r.Enabled {
			active[r.ID] = true
		}
	}
	seenScenario := map[string]bool{}
	seenCase := map[string]bool{}
	for _, s := range suite.Scenarios {
		if s.ID == "" || seenScenario[s.ID] || len(s.TargetRules) == 0 || len(s.Cases) == 0 {
			return suite, fmt.Errorf("invalid/duplicate scenario %q", s.ID)
		}
		seenScenario[s.ID] = true
		for _, rule := range s.TargetRules {
			if !active[rule] {
				return suite, fmt.Errorf("scenario %s targets disabled or unknown rule %s", s.ID, rule)
			}
		}
		pos, neg := 0, 0
		for _, c := range s.Cases {
			if c.ID == "" || seenCase[c.ID] || len(c.Events) == 0 {
				return suite, fmt.Errorf("invalid/duplicate case %q", c.ID)
			}
			seenCase[c.ID] = true
			if c.Label == "positive" {
				pos++
			} else if c.Label == "negative" {
				neg++
			} else {
				return suite, fmt.Errorf("invalid label for %s", c.ID)
			}
			for _, ev := range c.Events {
				if _, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err != nil {
					return suite, fmt.Errorf("case %s invalid timestamp: %w", c.ID, err)
				}
			}
		}
		if pos == 0 || neg == 0 {
			return suite, fmt.Errorf("scenario %s needs positive and negative cases", s.ID)
		}
	}
	return suite, nil
}
func ruleSets(alerts []model.SecurityAlert, targets []string) (target, other []string) {
	t := map[string]bool{}
	for _, v := range targets {
		t[v] = true
	}
	hit := map[string]bool{}
	extras := map[string]bool{}
	for _, a := range alerts {
		if t[a.RuleID] {
			hit[a.RuleID] = true
		} else {
			extras[a.RuleID] = true
		}
	}
	for v := range hit {
		target = append(target, v)
	}
	for v := range extras {
		other = append(other, v)
	}
	sort.Strings(target)
	sort.Strings(other)
	return
}
func verdict(label string, hit bool) (string, Counts) {
	switch {
	case label == "positive" && hit:
		return "TP", Counts{TP: 1}
	case label == "positive":
		return "FN", Counts{FN: 1}
	case hit:
		return "FP", Counts{FP: 1}
	default:
		return "TN", Counts{TN: 1}
	}
}
func makeReport(kind, suiteFile string, runs int) Report {
	return Report{SchemaVersion: "1.0", Kind: kind, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), SuiteFile: suiteFile, Runs: runs,
		Caveats: []string{
			"Labels are authored or manually assigned; results are conditional on this dataset, not real-world attack-detection accuracy.",
			"One trial counts once (TP/FP/FN/TN), even if multiple rules alert; unrelated rule alerts are listed separately.",
			"Zero-denominator metrics are represented numerically as 0 only for compatibility; consult precision_defined/recall_defined/f1_defined and NA in CSV.",
			"Indicator detections do not establish successful privilege escalation, container escape, cryptomining, or unauthorized workload creation.",
			"Alert timestamp represents event time, not wall-clock alert creation time. v0.9.6 writes detected_at and emitted_at; emitted_at marks write attempt, not fsync or ClickHouse persistence.",
			"Legacy alert logs without emitted_at cannot support latency calculations (NA).",
			"Missing telemetry is reported separately; end_to_end_recall includes independently confirmed, unobserved positive actions as misses; unobserved negatives are not TN.",
		}}
}
func msPtr(v float64) *float64 { return &v }
func (c *Coverage) AddStatus(status string) {
	switch status {
	case "observed":
		c.Actions++
		c.Observed++
	case "missing":
		c.Actions++
		c.Missing++
	case "partial":
		c.Actions++
		c.Partial++
	}
}
func (c *Coverage) Finish() {
	if c.Actions > 0 {
		c.Rate = msPtr(float64(c.Observed) / float64(c.Actions))
	}
}
func quantile(values []float64, p float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	x := p * float64(len(sorted)-1)
	lo := int(x)
	hi := lo + 1
	if hi >= len(sorted) {
		return msPtr(sorted[lo])
	}
	return msPtr(sorted[lo] + (sorted[hi]-sorted[lo])*(x-float64(lo)))
}
func latencyStats(values []float64) LatencySummary {
	return LatencySummary{Samples: len(values), P50Ms: quantile(values, 0.50), P95Ms: quantile(values, 0.95), P99Ms: quantile(values, 0.99)}
}

func finalize(r *Report, suite Suite) {
	byID := map[string]*ScenarioResult{}
	for _, s := range suite.Scenarios {
		r.ByScenario = append(r.ByScenario, ScenarioResult{ID: s.ID, Title: s.Title, TargetRules: s.TargetRules})
	}
	for i := range r.ByScenario {
		byID[r.ByScenario[i].ID] = &r.ByScenario[i]
	}
	latenciesByScenario := map[string][]float64{}
	totalLatencies := []float64{}
	for _, t := range r.Trials {
		v := byID[t.Scenario]
		if v == nil {
			continue
		}
		v.Coverage.AddStatus(t.TelemetryStatus)
		r.Coverage.AddStatus(t.TelemetryStatus)
		if t.TelemetryStatus == "missing" || t.TelemetryStatus == "partial" {
			if t.Label == "positive" {
				r.EndToEnd.FN++ /* scenario E2E below */
			}
			continue
		}
		if t.LatencyMs != nil {
			latenciesByScenario[t.Scenario] = append(latenciesByScenario[t.Scenario], *t.LatencyMs)
			totalLatencies = append(totalLatencies, *t.LatencyMs)
		}
		c := Counts{}
		switch t.Confusion {
		case "TP":
			c.TP = 1
		case "FP":
			c.FP = 1
		case "FN":
			c.FN = 1
		case "TN":
			c.TN = 1
		}
		v.Counts.Add(c)
		v.Evaluated = true
		r.Counts.Add(c)
		r.EndToEnd.Add(c)
	}
	r.Coverage.Finish()
	r.Latency = latencyStats(totalLatencies)
	if r.EndToEnd.TP+r.EndToEnd.FN > 0 {
		r.EndToEndRecall = msPtr(r.EndToEnd.Recall())
	}
	for i := range r.ByScenario {
		v := &r.ByScenario[i]
		v.Coverage.Finish()
		v.Latency = latencyStats(latenciesByScenario[v.ID])
		e2eTP := v.TP
		e2eFN := v.FN
		for _, t := range r.Trials {
			if t.Scenario == v.ID && t.Label == "positive" && (t.TelemetryStatus == "missing" || t.TelemetryStatus == "partial") {
				e2eFN++
			}
		}
		if e2eTP+e2eFN > 0 {
			v.EndToEndRecall = msPtr(float64(e2eTP) / float64(e2eTP+e2eFN))
		}
		v.Precision = v.Counts.Precision()
		v.Recall = v.Counts.Recall()
		v.F1 = v.Counts.F1()
		v.PrecisionDefined = v.TP+v.FP > 0
		v.RecallDefined = v.TP+v.FN > 0
		v.F1Defined = v.PrecisionDefined && v.RecallDefined
	}
	r.Precision = r.Counts.Precision()
	r.Recall = r.Counts.Recall()
	r.F1 = r.Counts.F1()
	r.PrecisionDefined = r.TP+r.FP > 0
	r.RecallDefined = r.TP+r.FN > 0
	r.F1Defined = r.PrecisionDefined && r.RecallDefined
}

type RunOptions struct {
	Suite, Rules, Correlations string
	Runs                       int
}

func RunSynthetic(o RunOptions) (Report, error) {
	var empty Report
	if o.Runs < 1 || o.Runs > 100 {
		return empty, fmt.Errorf("runs must be 1..100; repeated fixtures are NOT independent observations")
	}
	rc, e := detection.Load(o.Rules)
	if e != nil {
		return empty, e
	}
	cc, e := correlation.Load(o.Correlations)
	if e != nil {
		return empty, e
	}
	suite, e := loadSuite(o.Suite, rc, cc)
	if e != nil {
		return empty, e
	}
	r := makeReport("synthetic-labelled-detection-quality", o.Suite, o.Runs)
	r.Caveats = append(r.Caveats, "Synthetic pre-normalized events do not measure Tetragon/eBPF capture, Kubernetes API audit delivery, or production false-alert rates.", "Repeated deterministic fixture runs are regression checks, not independent statistical samples.")
	for _, s := range suite.Scenarios {
		for _, c := range s.Cases {
			for n := 1; n <= o.Runs; n++ {
				engine, e := detection.New(rc)
				if e != nil {
					return empty, e
				}
				corr, e := correlation.NewWithLateness(cc, 2*time.Second)
				if e != nil {
					return empty, e
				}
				alerts := []model.SecurityAlert{}
				for i, src := range c.Events {
					ev := src
					ev.EventID = fmt.Sprintf("%s-%d-%d", c.ID, n, i)
					hits, err := engine.Evaluate(ev)
					if err != nil {
						return empty, fmt.Errorf("%s: %w", c.ID, err)
					}
					alerts = append(alerts, hits...)
					hits, err = corr.Observe(ev)
					if err != nil {
						return empty, fmt.Errorf("%s: %w", c.ID, err)
					}
					alerts = append(alerts, hits...)
				}
				hits, e := corr.Flush()
				if e != nil {
					return empty, e
				}
				alerts = append(alerts, hits...)
				target, other := ruleSets(alerts, s.TargetRules)
				v, _ := verdict(c.Label, len(target) > 0)
				r.Trials = append(r.Trials, TrialResult{TrialID: c.ID, Scenario: s.ID, Label: c.Label, Repeat: n, Confusion: v, TargetRules: s.TargetRules, ObservedTargetRules: target, OtherObservedRules: other, TelemetryStatus: "synthetic"})
			}
		}
	}
	finalize(&r, suite)
	return r, nil
}

func readJSONLPaths(spec string, requireRecords bool, consume func([]byte) error) error {
	if strings.TrimSpace(spec) == "" {
		return fmt.Errorf("events/alerts path is required")
	}
	count := 0
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		matches, e := filepath.Glob(p)
		if e != nil {
			return e
		}
		if len(matches) == 0 {
			return fmt.Errorf("no JSONL files matching %q", p)
		}
		sort.Strings(matches)
		for _, file := range matches {
			f, e := os.Open(file)
			if e != nil {
				return e
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
			line := 0
			for scanner.Scan() {
				line++
				b := scanner.Bytes()
				if len(strings.TrimSpace(string(b))) == 0 {
					continue
				}
				if e = consume(b); e != nil {
					f.Close()
					return fmt.Errorf("%s:%d: %w", file, line, e)
				}
				count++
			}
			e = scanner.Err()
			f.Close()
			if e != nil {
				return fmt.Errorf("%s: %w", file, e)
			}
		}
	}
	if requireRecords && count == 0 {
		return fmt.Errorf("all JSONL inputs empty")
	}
	return nil
}

// InputSHA256 identifies the rule/suite files used for reproducible scoring.
// Runtime log files can be large and are intentionally not hashed by this helper.
func AddHashes(r *Report, paths ...string) error {
	r.InputSHA256 = map[string]string{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		r.InputSHA256[p] = fmt.Sprintf("%x", sum)
	}
	return nil
}
func Write(r Report, dir string) error {
	if e := os.MkdirAll(dir, 0750); e != nil {
		return e
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "quality.json"), append(b, '\n'), 0640); e != nil {
		return e
	}
	path := filepath.Join(dir, "quality-summary.csv")
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	w := csv.NewWriter(f)
	w.Write([]string{"scenario", "evaluated", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "actions", "observed", "missing", "partial", "telemetry_coverage", "end_to_end_recall", "latency_samples", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms"})
	metric := func(value float64, defined bool) string {
		if !defined {
			return "NA"
		}
		return fmt.Sprintf("%.4f", value)
	}
	numeric := func(v *float64) string {
		if v == nil {
			return "NA"
		}
		return fmt.Sprintf("%.4f", *v)
	}
	extra := func(c Coverage, e2e *float64, latency LatencySummary) []string {
		return []string{fmt.Sprint(c.Actions), fmt.Sprint(c.Observed), fmt.Sprint(c.Missing), fmt.Sprint(c.Partial), numeric(c.Rate), numeric(e2e), fmt.Sprint(latency.Samples), numeric(latency.P50Ms), numeric(latency.P95Ms), numeric(latency.P99Ms)}
	}
	for _, s := range r.ByScenario {
		w.Write(append([]string{s.ID, fmt.Sprint(s.Evaluated), fmt.Sprint(s.TP), fmt.Sprint(s.FP), fmt.Sprint(s.FN), fmt.Sprint(s.TN), metric(s.Precision, s.PrecisionDefined), metric(s.Recall, s.RecallDefined), metric(s.F1, s.F1Defined)}, extra(s.Coverage, s.EndToEndRecall, s.Latency)...))
	}
	w.Write(append([]string{"TOTAL", "true", fmt.Sprint(r.TP), fmt.Sprint(r.FP), fmt.Sprint(r.FN), fmt.Sprint(r.TN), metric(r.Precision, r.PrecisionDefined), metric(r.Recall, r.RecallDefined), metric(r.F1, r.F1Defined)}, extra(r.Coverage, r.EndToEndRecall, r.Latency)...))
	w.Flush()
	e = w.Error()
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	f, e = os.Create(filepath.Join(dir, "quality-trials.csv"))
	if e != nil {
		return e
	}
	w = csv.NewWriter(f)
	w.Write([]string{"scenario", "trial_id", "repeat", "label", "confusion", "target_rules", "observed_target_rules", "other_observed_rules", "source_event_ids", "telemetry_status", "missing_event_ids", "action_id", "latency_ms", "event_to_detection_ms", "expected_events", "observed_events"})
	for _, t := range r.Trials {
		w.Write([]string{t.Scenario, t.TrialID, fmt.Sprint(t.Repeat), t.Label, t.Confusion, strings.Join(t.TargetRules, ";"), strings.Join(t.ObservedTargetRules, ";"), strings.Join(t.OtherObservedRules, ";"), strings.Join(t.SourceEventIDs, ";"), t.TelemetryStatus, strings.Join(t.MissingEventIDs, ";"), t.ActionID, numeric(t.LatencyMs), numeric(t.EventToDetectionMs), fmt.Sprint(t.ExpectedEvents), fmt.Sprint(t.ObservedEvents)})
	}
	w.Flush()
	e = w.Error()
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return WriteLatencyCSV(r, dir)
}

// WriteLatencyCSV appends a machine-readable, per-trial measurement log.
func WriteLatencyCSV(r Report, dir string) error {
	f, err := os.Create(filepath.Join(dir, "quality-latency.csv"))
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"scenario", "trial_id", "action_started_at", "first_target_alert_emitted_at", "action_to_alert_ms", "event_to_detection_ms"})
	value := func(v *float64) string {
		if v == nil {
			return "NA"
		}
		return fmt.Sprintf("%.4f", *v)
	}
	for _, t := range r.Trials {
		_ = w.Write([]string{t.Scenario, t.TrialID, t.ActionStartedAt, t.FirstAlertEmittedAt, value(t.LatencyMs), value(t.EventToDetectionMs)})
	}
	w.Flush()
	err = w.Error()
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}
