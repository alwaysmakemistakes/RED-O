// Package benchmark runs reproducible, labelled, synthetic detection-engine
// experiments. Results are NOT measurements of Tetragon capture or Kubernetes.
package benchmark

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/model"
	"sort"
	"strconv"
	"time"
)

type Options struct {
	Runs                        int
	Lateness                    time.Duration
	Buffer                      int
	RulesFile, CorrelationsFile string
}
type ScenarioResult struct {
	Name       string         `json:"name"`
	Runs       int            `json:"runs"`
	Events     int            `json:"events"`
	Expected   []string       `json:"expected_rules"`
	Observed   map[string]int `json:"observed_counts"`
	TP         int            `json:"tp"`
	FP         int            `json:"fp"`
	FN         int            `json:"fn"`
	DurationNS int64          `json:"duration_ns"`
}
type Report struct {
	SchemaVersion         string           `json:"schema_version"`
	Kind                  string           `json:"kind"`
	GeneratedAt           string           `json:"generated_at"`
	RulesFile             string           `json:"rules_file"`
	CorrelationsFile      string           `json:"correlations_file"`
	RunsPerScenario       int              `json:"runs_per_scenario"`
	Lateness              string           `json:"lateness"`
	Buffer                int              `json:"buffer"`
	GoVersion             string           `json:"go_version"`
	Scenarios             []ScenarioResult `json:"scenarios"`
	TP                    int              `json:"tp"`
	FP                    int              `json:"fp"`
	FN                    int              `json:"fn"`
	Precision             float64          `json:"precision"`
	Recall                float64          `json:"recall"`
	F1                    float64          `json:"f1"`
	Events                int              `json:"events"`
	DurationNS            int64            `json:"duration_ns"`
	EngineEventsPerSecond float64          `json:"engine_events_per_second"`
	Caveat                string           `json:"caveat"`
}

type spec struct {
	name     string
	events   []model.SecurityEvent
	expected []string
}

var origin = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func event(id, kind, binary, execID, parent, path, ip, ns, container string, second int) model.SecurityEvent {
	return model.SecurityEvent{
		SchemaVersion: "1.0", EventID: id, EventType: kind, Timestamp: origin.Add(time.Duration(second) * time.Second).Format(time.RFC3339Nano), Node: "benchmark-node",
		Process:    model.Process{ExecID: execID, ParentExecID: parent, Binary: binary},
		Kubernetes: &model.Kubernetes{Namespace: ns, Pod: "benchmark-pod", PodUID: "pod-" + container, ContainerID: container},
		File:       &model.File{Path: path}, Network: &model.Network{DestinationIP: ip, DestinationPort: 443},
	}
}
func fixtures() []spec {
	shell := event("shell", "process.exec", "/bin/sh", "shell", "", "", "", "security-lab", "a", 0)
	file := event("file", "file.access", "/bin/cat", "reader", "shell", "/etc/passwd", "", "security-lab", "a", 1)
	net := event("net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "a", 2)
	token := event("token", "file.access", "/usr/local/bin/python3", "python", "", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10_14_54_18.3445112349/token", "", "security-lab", "a", 0)
	tokenNet := event("token-net", "network.connect", "/usr/local/bin/python3", "python", "", "", "1.1.1.1", "security-lab", "a", 1)
	token2 := token
	token2.EventID = "token2"
	wget := event("wget", "process.exec", "/bin/wget", "wget", "", "", "", "security-lab", "a", 0)
	wgetNet := event("wget-net", "network.connect", "/bin/wget", "wget", "", "", "1.1.1.1", "security-lab", "a", 1)
	return []spec{
		{"shell-file-network-reordered", []model.SecurityEvent{net, shell, file}, []string{"R001", "R003", "R005", "R006"}},
		{"dynamic-token-network", []model.SecurityEvent{tokenNet, token}, []string{"R003", "R007"}},
		{"duplicate-token-one-network", []model.SecurityEvent{token2, token, tokenNet}, []string{"R003", "R007"}},
		{"wget-network", []model.SecurityEvent{wgetNet, wget}, []string{"R003", "R004", "R008"}},
		{"sensitive-file", []model.SecurityEvent{event("shadow", "file.access", "/bin/cat", "reader", "", "/etc/shadow", "", "security-lab", "a", 0)}, []string{"R002"}},
		{"unrelated-process", []model.SecurityEvent{shell, event("unrelated-net", "network.connect", "/bin/wget", "other", "otherroot", "", "1.1.1.1", "security-lab", "a", 1)}, []string{"R001", "R003"}},
		{"different-container", []model.SecurityEvent{shell, event("foreign-net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "b", 1)}, []string{"R001", "R003"}},
		{"outside-namespace", []model.SecurityEvent{event("ns-shell", "process.exec", "/bin/sh", "shell", "", "", "", "default", "a", 0), event("ns-net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "default", "a", 1)}, nil},
		{"unmonitored-destination", []model.SecurityEvent{shell, event("safe-net", "network.connect", "/bin/wget", "wget", "shell", "", "9.9.9.9", "security-lab", "a", 1)}, []string{"R001"}},
		{"outside-window", []model.SecurityEvent{shell, event("far-net", "network.connect", "/bin/wget", "wget", "shell", "", "1.1.1.1", "security-lab", "a", 61)}, []string{"R001", "R003"}},
		{"token-without-network", []model.SecurityEvent{token}, nil},
		{"token-unrelated-network", []model.SecurityEvent{token, event("other-net", "network.connect", "/bin/wget", "other", "different", "", "1.1.1.1", "security-lab", "a", 1)}, []string{"R003"}},
		{"normal-nonmatching-file", []model.SecurityEvent{event("normal-file", "file.access", "/usr/local/bin/python3", "python", "", "/run/secrets/kubernetes.io/serviceaccount/..2026_11_10_14_54_18.3445112349/ca.crt", "", "security-lab", "a", 0)}, nil},
	}
}
func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
func Run(o Options) (Report, error) {
	var report Report
	if o.Runs < 1 || o.Runs > 10000 {
		return report, fmt.Errorf("runs must be between 1 and 10000")
	}
	if o.Buffer < 1 {
		return report, fmt.Errorf("buffer must be >=1")
	}
	if o.Lateness < 0 || o.Lateness > time.Minute {
		return report, fmt.Errorf("lateness must be between 0 and 1m")
	}
	rc, err := detection.Load(o.RulesFile)
	if err != nil {
		return report, err
	}
	cc, err := correlation.Load(o.CorrelationsFile)
	if err != nil {
		return report, err
	}
	// Historical 13 labelled fixtures were authored for R001–R008 only.
	// Preserve their ground truth rather than misclassifying newly introduced
	// rule alerts as false positives. Extended rule quality has its own suite.
	legacyRules := rc.Rules[:0]
	for _, rule := range rc.Rules {
		if len(rule.ID) == 4 && rule.ID >= "R001" && rule.ID <= "R008" {
			legacyRules = append(legacyRules, rule)
		}
	}
	rc.Rules = legacyRules
	legacyCorrelations := cc.Rules[:0]
	for _, rule := range cc.Rules {
		if len(rule.ID) == 4 && rule.ID >= "R001" && rule.ID <= "R008" {
			legacyCorrelations = append(legacyCorrelations, rule)
		}
	}
	cc.Rules = legacyCorrelations
	engine, err := detection.New(rc)
	if err != nil {
		return report, err
	}
	report = Report{SchemaVersion: "1.0", Kind: "synthetic-labelled-engine-benchmark", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), RulesFile: o.RulesFile, CorrelationsFile: o.CorrelationsFile, RunsPerScenario: o.Runs, Lateness: o.Lateness.String(), Buffer: o.Buffer, GoVersion: runtime.Version(), Caveat: "Legacy fixtures evaluate only R001–R008. Synthetic normalized events. Metrics are engine-only, not Kubernetes/Tetragon capture latency, end-to-end latency, real-world detection precision, or measured loss."}
	overall := time.Now()
	for _, s := range fixtures() {
		sr := ScenarioResult{Name: s.name, Runs: o.Runs, Expected: append([]string{}, s.expected...), Observed: make(map[string]int)}
		start := time.Now()
		for n := 0; n < o.Runs; n++ {
			corr, e := correlation.NewWithLateness(cc, o.Lateness)
			if e != nil {
				return report, e
			}
			if e = corr.SetBufferLimit(o.Buffer); e != nil {
				return report, e
			}
			observed := make(map[string]int)
			for _, orig := range s.events {
				// Unique IDs per repetition; process ancestry remains intact inside each repetition.
				ev := orig
				ev.EventID = fmt.Sprintf("%s-run-%d", orig.EventID, n)
				sr.Events++
				alerts, e := engine.Evaluate(ev)
				if e != nil {
					return report, e
				}
				for _, a := range alerts {
					observed[a.RuleID]++
				}
				alerts, e = corr.Observe(ev)
				if e != nil {
					return report, e
				}
				for _, a := range alerts {
					observed[a.RuleID]++
				}
			}
			alerts, e := corr.Flush()
			if e != nil {
				return report, e
			}
			for _, a := range alerts {
				observed[a.RuleID]++
			}
			expected := make(map[string]int)
			for _, id := range s.expected {
				expected[id]++
			}
			keys := make(map[string]bool)
			for id := range observed {
				keys[id] = true
			}
			for id := range expected {
				keys[id] = true
			}
			for id := range keys {
				a, b := observed[id], expected[id]
				if a < b {
					sr.TP += a
					sr.FN += b - a
				} else {
					sr.TP += b
					sr.FP += a - b
				}
				sr.Observed[id] += a
			}
		}
		sr.DurationNS = time.Since(start).Nanoseconds()
		report.Scenarios = append(report.Scenarios, sr)
		report.TP += sr.TP
		report.FP += sr.FP
		report.FN += sr.FN
		report.Events += sr.Events
	}
	report.DurationNS = time.Since(overall).Nanoseconds()
	report.Precision = ratio(report.TP, report.TP+report.FP)
	report.Recall = ratio(report.TP, report.TP+report.FN)
	if report.Precision+report.Recall > 0 {
		report.F1 = 2 * report.Precision * report.Recall / (report.Precision + report.Recall)
	}
	if report.DurationNS > 0 {
		report.EngineEventsPerSecond = float64(report.Events) / float64(report.DurationNS) * 1e9
	}
	return report, nil
}
func Write(report Report, jsonPath, csvPath string) error {
	for _, p := range []string{jsonPath, csvPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return err
		}
	}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(jsonPath, append(b, '\n'), 0600); e != nil {
		return e
	}
	f, e := os.Create(csvPath)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if e = w.Write([]string{"scenario", "runs", "events", "expected_rules", "observed_rules", "tp", "fp", "fn", "duration_ms"}); e != nil {
		return e
	}
	for _, s := range report.Scenarios {
		observed := make([]string, 0, len(s.Observed))
		for id, n := range s.Observed {
			observed = append(observed, fmt.Sprintf("%s:%d", id, n))
		}
		sort.Strings(observed)
		row := []string{s.Name, strconv.Itoa(s.Runs), strconv.Itoa(s.Events), fmt.Sprint(s.Expected), fmt.Sprint(observed), strconv.Itoa(s.TP), strconv.Itoa(s.FP), strconv.Itoa(s.FN), fmt.Sprintf("%.3f", float64(s.DurationNS)/1e6)}
		if e = w.Write(row); e != nil {
			return e
		}
	}
	w.Flush()
	return w.Error()
}
