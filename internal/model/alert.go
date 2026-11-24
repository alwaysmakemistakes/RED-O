package model

// SecurityAlert is a detection result referencing a normalized event.
type SecurityAlert struct {
	SchemaVersion   string             `json:"schema_version"`
	AlertID         string             `json:"alert_id"`
	RuleID          string             `json:"rule_id"`
	RuleName        string             `json:"rule_name"`
	Severity        string             `json:"severity"`
	Status          string             `json:"status"`
	Timestamp       string             `json:"timestamp"`
	DetectedAt      string             `json:"detected_at,omitempty"` // UTC: detection decision instant (not the event timestamp)
	EmittedAt       string             `json:"emitted_at,omitempty"`  // UTC: output write attempt instant (not disk fsync)
	Evidence        *AlertEvidence     `json:"evidence,omitempty"`
	Context         *ContextAssessment `json:"context,omitempty"`
	Description     string             `json:"description"`
	Reason          string             `json:"reason"`
	Kubernetes      *Kubernetes        `json:"kubernetes,omitempty"`
	RelatedEventIDs []string           `json:"related_event_ids"`
	SensorIDs       []string           `json:"sensor_ids,omitempty"`
	Cluster         string             `json:"cluster,omitempty"`
}

// AlertEvidence documents an evidence window for behavioral/deduplicated alerts.
// RelatedEventIDs contains the corresponding normalized evidence records.
type AlertEvidence struct {
	WindowStart          string   `json:"window_start,omitempty"`
	WindowEnd            string   `json:"window_end,omitempty"`
	WindowSeconds        int      `json:"window_seconds,omitempty"`
	DistinctDestinations int      `json:"distinct_destinations,omitempty"`
	Threshold            int      `json:"threshold,omitempty"`
	DestinationIPs       []string `json:"destination_ips,omitempty"`
}

// ContextAssessment is advisory enrichment of the original signature alert.
// Original Severity and the underlying alert remain unchanged, including when
// triage_action=approved. Only an independent policy may establish approval.
type ContextAssessment struct {
	PolicyID          string `json:"policy_id,omitempty"`
	Decision          string `json:"decision"`      // unmatched, approved, elevate, incomplete_evidence
	TriageAction      string `json:"triage_action"` // approved or review
	OriginalSeverity  string `json:"original_severity"`
	RiskScore         int    `json:"risk_score"`
	RiskLevel         string `json:"risk_level"`
	EffectiveSeverity string `json:"effective_severity"`
	EvidenceComplete  bool   `json:"evidence_complete"`
	Explanation       string `json:"explanation"`
}
