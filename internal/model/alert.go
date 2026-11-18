package model

// SecurityAlert is a detection result referencing a normalized event.
type SecurityAlert struct {
	SchemaVersion   string      `json:"schema_version"`
	AlertID         string      `json:"alert_id"`
	RuleID          string      `json:"rule_id"`
	RuleName        string      `json:"rule_name"`
	Severity        string      `json:"severity"`
	Status          string      `json:"status"`
	Timestamp       string      `json:"timestamp"`
	Description     string      `json:"description"`
	Reason          string      `json:"reason"`
	Kubernetes      *Kubernetes `json:"kubernetes,omitempty"`
	RelatedEventIDs []string    `json:"related_event_ids"`
}
