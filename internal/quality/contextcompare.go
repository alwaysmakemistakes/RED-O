package quality

// Context comparison replays original, immutable alerts through advisory
// context policies and evaluates a counterfactual triage queue. No source
// events or alerts are modified, no detector is restarted, and an analyst's
// authorization/ground truth is never inferred from the alerts themselves.

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"runtime-detector/internal/contextpolicy"
	"runtime-detector/internal/model"
)

type CompareOptions struct {
	Live          LiveOptions
	ContextPolicy string
	Output        string
}
type Score struct {
	Counts
	Precision      float64  `json:"precision"`
	Recall         float64  `json:"recall"`
	F1             float64  `json:"f1"`
	Coverage       Coverage `json:"coverage"`
	EndToEndRecall *float64 `json:"end_to_end_recall,omitempty"`
}
type CompareTrial struct {
	TrialID    string `json:"trial_id"`
	Scenario   string `json:"scenario"`
	Label      string `json:"label"`
	Baseline   string `json:"baseline"`
	Contextual string `json:"contextual"`
	Telemetry  string `json:"telemetry_status"`
}
type TriageDecision struct {
	AlertID         string                  `json:"alert_id"`
	RuleID          string                  `json:"rule_id"`
	RelatedEventIDs []string                `json:"related_event_ids"`
	Assessment      model.ContextAssessment `json:"assessment"`
}
type Comparison struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	PolicySHA256  string         `json:"policy_sha256"`
	Baseline      Score          `json:"baseline"`
	Contextual    Score          `json:"contextual"`
	Decisions     int            `json:"decisions"`
	Approved      int            `json:"approved"`
	Elevated      int            `json:"elevated"`
	Incomplete    int            `json:"incomplete"`
	Unmatched     int            `json:"unmatched"`
	Trials        []CompareTrial `json:"trials"`
	Caveats       []string       `json:"caveats"`
}

func score(r Report) Score {
	return Score{Counts: r.Counts, Precision: r.Precision, Recall: r.Recall, F1: r.F1, Coverage: r.Coverage, EndToEndRecall: r.EndToEndRecall}
}

func CompareLive(o CompareOptions) (Comparison, error) {
	var result Comparison
	if o.ContextPolicy == "" || o.Output == "" {
		return result, fmt.Errorf("context comparison requires policy and output paths")
	}
	if !o.Live.StrictAttribution {
		return result, fmt.Errorf("context comparison requires strict attribution")
	}
	cfg, err := contextpolicy.Load(o.ContextPolicy)
	if err != nil {
		return result, err
	}
	policyBytes, err := os.ReadFile(o.ContextPolicy)
	if err != nil {
		return result, err
	}
	policySHA := sha256.Sum256(policyBytes)
	baseline, err := EvaluateLive(o.Live)
	if err != nil {
		return result, fmt.Errorf("baseline evaluation: %w", err)
	}
	if err := AddHashes(&baseline, o.Live.Suite, o.Live.Rules, o.Live.Correlations, o.Live.Manifest); err != nil {
		return result, fmt.Errorf("baseline input hashes: %w", err)
	}
	mb, err := os.ReadFile(o.Live.Manifest)
	if err != nil {
		return result, err
	}
	var m Manifest
	if err = json.Unmarshal(mb, &m); err != nil {
		return result, err
	}
	owner := map[string]bool{}
	for _, t := range m.Trials {
		for _, id := range t.EventIDs {
			owner[id] = true
		}
	}
	// Collect only the evidence linked to a labelled trial.
	relevant := []model.SecurityAlert{}
	wanted := map[string]bool{}
	if err = readJSONLPaths(o.Live.Alerts, false, func(line []byte) error {
		var a model.SecurityAlert
		if err := json.Unmarshal(line, &a); err != nil {
			return err
		}
		belongs := false
		for _, id := range a.RelatedEventIDs {
			if owner[id] {
				belongs = true
				break
			}
		}
		if !belongs {
			return nil
		}
		relevant = append(relevant, a)
		for _, id := range a.RelatedEventIDs {
			wanted[id] = true
		}
		return nil
	}); err != nil {
		return result, err
	}
	evidence := map[string]model.SecurityEvent{}
	if err = readJSONLPaths(o.Live.Events, false, func(line []byte) error {
		var header struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(line, &header); err != nil {
			return err
		}
		if !wanted[header.EventID] {
			return nil
		}
		if _, exists := evidence[header.EventID]; exists {
			return fmt.Errorf("duplicated evidence event ID %s", header.EventID)
		}
		var e model.SecurityEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		evidence[e.EventID] = e
		return nil
	}); err != nil {
		return result, err
	}
	if err = os.MkdirAll(o.Output, 0750); err != nil {
		return result, err
	}
	tempDir, err := os.MkdirTemp("", "redo-context-compare-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(tempDir)
	filtered, err := os.OpenFile(filepath.Join(tempDir, "contextual-alerts.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	defer filtered.Close()
	decisionsPath := filepath.Join(o.Output, "triage-decisions.jsonl")
	decisions, err := os.OpenFile(decisionsPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	defer decisions.Close()
	result = Comparison{SchemaVersion: "1.0", Kind: "advisory-context-counterfactual", PolicySHA256: hex.EncodeToString(policySHA[:]), Baseline: score(baseline), Caveats: []string{
		"Baseline and contextual scores use the SAME immutable source events, original alerts and independent trial labels.",
		"Contextual results simulate an analyst triage queue: approved alerts remain stored in Detector/ClickHouse and are only excluded from counterfactual scoring.",
		"Policies must be specified before held-out evaluation; allowlisting the same test identifiers after viewing labels leaks ground truth and cannot establish generalizable precision gains.",
		"No automatic attack authorization inference or machine-learning model is claimed.",
		"Counterfactual latency uses retained alert emitted_at only; actual review times and analyst workloads were not measured.",
	}}
	for _, a := range relevant {
		evs := make([]model.SecurityEvent, 0, len(a.RelatedEventIDs))
		complete := len(a.RelatedEventIDs) > 0
		seenIDs := map[string]bool{}
		for _, id := range a.RelatedEventIDs {
			ev, ok := evidence[id]
			if !ok || seenIDs[id] {
				complete = false
				continue
			}
			seenIDs[id] = true
			evs = append(evs, ev)
		}
		assessment := cfg.Assess(a, evs, complete && len(evs) == len(a.RelatedEventIDs))
		a.Context = &assessment
		switch assessment.Decision {
		case "approved":
			result.Approved++
		case "elevate":
			result.Elevated++
		case "incomplete_evidence":
			result.Incomplete++
		default:
			result.Unmatched++
		}
		result.Decisions++
		if err = json.NewEncoder(decisions).Encode(TriageDecision{AlertID: a.AlertID, RuleID: a.RuleID, RelatedEventIDs: a.RelatedEventIDs, Assessment: assessment}); err != nil {
			return result, err
		}
		if assessment.TriageAction != "approved" {
			if err = json.NewEncoder(filtered).Encode(a); err != nil {
				return result, err
			}
		}
	}
	if err = filtered.Close(); err != nil {
		return result, err
	}
	if err = decisions.Close(); err != nil {
		return result, err
	}
	if err = Write(baseline, filepath.Join(o.Output, "baseline")); err != nil {
		return result, err
	}
	counterOpt := o.Live
	counterOpt.Alerts = filtered.Name()
	contextual, err := EvaluateLive(counterOpt)
	if err != nil {
		return result, fmt.Errorf("contextual evaluation: %w", err)
	}
	if err := AddHashes(&contextual, o.Live.Suite, o.Live.Rules, o.Live.Correlations, o.Live.Manifest, o.ContextPolicy); err != nil {
		return result, fmt.Errorf("context input hashes: %w", err)
	}
	contextual.Kind = "live-context-advisory-counterfactual"
	contextual.Caveats = append(contextual.Caveats, "Approved context policies are an offline triage hypothesis, not a change to RED-O raw rule alert emission.")
	if err = Write(contextual, filepath.Join(o.Output, "contextual")); err != nil {
		return result, err
	}
	result.Contextual = score(contextual)
	baselineTrials := map[string]TrialResult{}
	for _, t := range baseline.Trials {
		baselineTrials[t.TrialID] = t
	}
	for _, t := range contextual.Trials {
		b, ok := baselineTrials[t.TrialID]
		if !ok {
			return result, fmt.Errorf("trial missing in baseline %s", t.TrialID)
		}
		result.Trials = append(result.Trials, CompareTrial{TrialID: t.TrialID, Scenario: t.Scenario, Label: t.Label, Baseline: b.Confusion, Contextual: t.Confusion, Telemetry: t.TelemetryStatus})
	}
	sort.Slice(result.Trials, func(i, j int) bool { return result.Trials[i].TrialID < result.Trials[j].TrialID })
	file, err := os.OpenFile(filepath.Join(o.Output, "comparison.json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(result)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	f, err := os.OpenFile(filepath.Join(o.Output, "comparison-trials.csv"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	w := csv.NewWriter(f)
	if err = w.Write([]string{"trial_id", "scenario", "label", "telemetry", "baseline", "contextual"}); err != nil {
		f.Close()
		return result, err
	}
	for _, t := range result.Trials {
		if err = w.Write([]string{t.TrialID, t.Scenario, t.Label, t.Telemetry, t.Baseline, t.Contextual}); err != nil {
			f.Close()
			return result, err
		}
	}
	w.Flush()
	err = w.Error()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	return result, nil
}
