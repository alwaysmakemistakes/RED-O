package quality

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"runtime-detector/internal/correlation"
	"runtime-detector/internal/detection"
	"runtime-detector/internal/model"
)

// LiveOptions keeps the v0.9.5 file-based evaluator; StrictAttribution is
// opt-in for API callers and on by default in the v0.9.6 CLI.
type LiveOptions struct {
	Suite, Rules, Correlations, Manifest, Events, Alerts string
	StrictAttribution                                    bool
}

func parseUTC(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func validateAction(t Trial) error {
	if t.ExpectedEvents < 0 || t.ExpectedEvents > 10000 {
		return fmt.Errorf("trial %s: expected_events must be 0..10000", t.ID)
	}
	if strings.TrimSpace(t.ActionID) == "" || t.ActionStatus != "completed" {
		return fmt.Errorf("trial %s: schema 1.1 requires nonempty action_id and action_status=completed recorded independently of telemetry", t.ID)
	}
	start, e := parseUTC(t.ActionStartedAt)
	if e != nil {
		return fmt.Errorf("trial %s: invalid action_started_at: %w", t.ID, e)
	}
	end, e := parseUTC(t.ActionFinishedAt)
	if e != nil {
		return fmt.Errorf("trial %s: invalid action_finished_at: %w", t.ID, e)
	}
	if end.Before(start) {
		return fmt.Errorf("trial %s: action ends before start", t.ID)
	}
	return nil
}

// EvaluateLive preserves strict v1.0 semantics; v1.1 additionally accepts
// independently documented completed actions with missing collector evidence.
// Such actions are *not* automatically classified TN and remain visible in
// coverage statistics. An unobserved positive is an end-to-end miss, not a
// conditional rule-engine false negative.
func EvaluateLive(o LiveOptions) (Report, error) {
	var empty Report
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
	b, e := os.ReadFile(o.Manifest)
	if e != nil {
		return empty, e
	}
	var m Manifest
	if e = json.Unmarshal(b, &m); e != nil {
		return empty, fmt.Errorf("manifest: %w", e)
	}
	if (m.SchemaVersion != "1.0" && m.SchemaVersion != "1.1") || len(m.Trials) == 0 {
		return empty, fmt.Errorf("manifest requires schema_version 1.0 or 1.1 and nonempty trials")
	}
	v11 := m.SchemaVersion == "1.1"
	scenarios := map[string]Scenario{}
	for _, s := range suite.Scenarios {
		scenarios[s.ID] = s
	}
	owner := map[string]string{}
	ids := map[string]bool{}
	trialSeen := map[string]bool{}
	actionSeen := map[string]bool{}
	for _, t := range m.Trials {
		if t.ID == "" || trialSeen[t.ID] {
			return empty, fmt.Errorf("missing/duplicate trial id %q", t.ID)
		}
		trialSeen[t.ID] = true
		if _, ok := scenarios[t.Scenario]; !ok {
			return empty, fmt.Errorf("unknown trial scenario %s", t.Scenario)
		}
		if t.Label != "positive" && t.Label != "negative" {
			return empty, fmt.Errorf("trial %s must have positive or negative label", t.ID)
		}
		if v11 {
			if e = validateAction(t); e != nil {
				return empty, e
			}
			if actionSeen[t.ActionID] {
				return empty, fmt.Errorf("action_id %s duplicated", t.ActionID)
			}
			actionSeen[t.ActionID] = true
		} else if len(t.EventIDs) == 0 {
			return empty, fmt.Errorf("trial %s has no event_ids; refusing to guess attribution by time window", t.ID)
		}
		for _, id := range t.EventIDs {
			if id == "" {
				return empty, fmt.Errorf("empty event_id for %s", t.ID)
			}
			if prev := owner[id]; prev != "" {
				return empty, fmt.Errorf("event_id %s reused between trials %s and %s", id, prev, t.ID)
			}
			owner[id] = t.ID
			ids[id] = true
		}
	}
	// Do not derive execution from the alerts or infer unobserved actions by
	// a lack of matching lines. Execution provenance is supplied by manifest.
	found := map[string]int{}
	if e = readJSONLPaths(o.Events, !v11, func(raw []byte) error {
		var v struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if ids[v.EventID] {
			found[v.EventID]++
		}
		return nil
	}); e != nil {
		return empty, e
	}
	for id := range ids {
		if found[id] > 1 {
			return empty, fmt.Errorf("source event_id %s occurs %d times in supplied events (need at most one)", id, found[id])
		}
		if !v11 && found[id] != 1 {
			return empty, fmt.Errorf("source event_id %s occurs %d times in supplied events (need exactly once)", id, found[id])
		}
	}
	byTrial := map[string][]model.SecurityAlert{}
	alertSeen := map[string]bool{}
	externalRefs := 0
	if e = readJSONLPaths(o.Alerts, false, func(raw []byte) error {
		var a model.SecurityAlert
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		targets := map[string]bool{}
		unseen := []string{}
		for _, id := range a.RelatedEventIDs {
			if t := owner[id]; t != "" {
				targets[t] = true
			} else {
				unseen = append(unseen, id)
			}
		}
		if len(targets) > 1 {
			return fmt.Errorf("alert %s spans different trial event_ids; trials are not isolated", a.AlertID)
		}
		if len(targets) == 0 {
			return nil
		}
		if len(unseen) > 0 {
			if o.StrictAttribution {
				return fmt.Errorf("alert %s mixes trial evidence with unassigned event_ids: %s; include all related event_ids in the same trial or disable -strict-attribution with explicit justification", a.AlertID, strings.Join(unseen, ","))
			}
			externalRefs++
		}
		if a.AlertID == "" {
			return fmt.Errorf("alert has no alert_id")
		}
		if alertSeen[a.AlertID] {
			return fmt.Errorf("duplicate alert_id %s", a.AlertID)
		}
		alertSeen[a.AlertID] = true
		for t := range targets {
			byTrial[t] = append(byTrial[t], a)
		}
		return nil
	}); e != nil {
		return empty, e
	}
	r := makeReport("live-labelled-event-id-evaluation", o.Suite, 1)
	r.Caveats = append(r.Caveats,
		"Live action labels, timestamps, and event IDs must be independently documented; benchmark does not certify manifest honesty.",
		"Input JSONL must cover all experiment time windows, including rotated segments; missing lines could instead indicate omitted input files.",
		"Legacy schema 1.0 manifests include only pre-observed event IDs; their apparent 100% coverage does not quantify collector losses. Use schema 1.1 with independent action records.",
		"Strict attribution rejects correlation alerts referencing unassigned evidence; list all event IDs for correlated trials.",
		"Coverage counts completed actions. Unobserved positives are counted as end-to-end misses, not as observed-only FN; unobserved negatives are neither TN nor FP.",
		"Latency requires action_started_at in schema 1.1 and alert emitted_at from a v0.9.6 detector. It measures action start to output write attempt, not disk durability or eBPF capture latency.",
	)
	if !o.StrictAttribution {
		r.Caveats = append(r.Caveats, fmt.Sprintf("WARNING: strict attribution disabled; %d attributed alerts referenced unrelated/unassigned evidence", externalRefs))
	}
	for _, t := range m.Trials {
		s := scenarios[t.Scenario]
		missing := []string{}
		observed := 0
		for _, id := range t.EventIDs {
			if found[id] == 1 {
				observed++
			} else {
				missing = append(missing, id)
			}
		}
		status := "observed"
		if observed == 0 {
			status = "missing"
		} else if len(missing) > 0 {
			status = "partial"
		}
		if v11 && len(t.EventIDs) == 0 {
			status = "missing"
		}
		if v11 && t.ExpectedEvents > 0 && observed > 0 && observed < t.ExpectedEvents {
			status = "partial"
		}
		target, other := ruleSets(byTrial[t.ID], s.TargetRules)
		verdictString := "UNOBSERVED"
		if status == "partial" {
			verdictString = "PARTIAL_TELEMETRY"
		}
		if status == "observed" {
			verdictString, _ = verdict(t.Label, len(target) > 0)
		}
		result := TrialResult{TrialID: t.ID, Scenario: t.Scenario, Label: t.Label, Repeat: 1, Confusion: verdictString, TargetRules: s.TargetRules, ObservedTargetRules: target, OtherObservedRules: other, SourceEventIDs: t.EventIDs, TelemetryStatus: status, MissingEventIDs: missing, ActionID: t.ActionID, ActionStartedAt: t.ActionStartedAt, ExpectedEvents: t.ExpectedEvents, ObservedEvents: observed}
		if status == "observed" && v11 && len(target) > 0 {
			start, _ := parseUTC(t.ActionStartedAt)
			type moment struct {
				a  model.SecurityAlert
				at time.Time
			}
			ordered := []moment{}
			targetSet := map[string]bool{}
			for _, id := range s.TargetRules {
				targetSet[id] = true
			}
			for _, a := range byTrial[t.ID] {
				if !targetSet[a.RuleID] || a.EmittedAt == "" {
					continue
				}
				at, err := parseUTC(a.EmittedAt)
				if err != nil {
					return empty, fmt.Errorf("alert %s has invalid emitted_at: %w", a.AlertID, err)
				}
				if at.Before(start) {
					return empty, fmt.Errorf("alert %s emitted before action start; possible bad attribution or clock skew", a.AlertID)
				}
				ordered = append(ordered, moment{a, at})
			}
			sort.Slice(ordered, func(i, j int) bool { return ordered[i].at.Before(ordered[j].at) })
			if len(ordered) > 0 {
				first := ordered[0]
				result.FirstAlertEmittedAt = first.a.EmittedAt
				result.LatencyMs = msPtr(float64(first.at.Sub(start).Nanoseconds()) / 1e6)
				if first.a.DetectedAt != "" && first.a.Timestamp != "" {
					detected, er1 := parseUTC(first.a.DetectedAt)
					eventTime, er2 := parseUTC(first.a.Timestamp)
					if er1 != nil || er2 != nil {
						return empty, fmt.Errorf("alert %s has invalid detected_at/timestamp", first.a.AlertID)
					}
					if !detected.Before(eventTime) {
						result.EventToDetectionMs = msPtr(float64(detected.Sub(eventTime).Nanoseconds()) / 1e6)
					}
				}
			}
		}
		r.Trials = append(r.Trials, result)
	}
	finalize(&r, suite)
	return r, nil
}
