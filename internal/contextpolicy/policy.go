// Package contextpolicy provides conservative, evidence-linked and explicitly
// approved context assessment. It NEVER changes source events or base rule hits.
package contextpolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"runtime-detector/internal/model"
)

// Match fields are conjunctive. An alert with more than one related event must
// remain in the same declared Kubernetes/sensor scope; event-specific fields
// can be satisfied by one of its evidence records.
type Match struct {
	Cluster           string `json:"cluster,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Pod               string `json:"pod,omitempty"`
	PodUID            string `json:"pod_uid,omitempty"`
	AuditUser         string `json:"audit_user,omitempty"`
	AuditResource     string `json:"audit_resource,omitempty"`
	AuditName         string `json:"audit_name,omitempty"`
	ProcessBinary     string `json:"process_binary,omitempty"`
	ArgumentsContains string `json:"arguments_contains,omitempty"`
	FilePathPrefix    string `json:"file_path_prefix,omitempty"`
	DestinationCIDR   string `json:"destination_cidr,omitempty"`
}

type Policy struct {
	ID         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	Decision   string   `json:"decision"` // approved | elevate
	Reason     string   `json:"reason"`
	RuleIDs    []string `json:"rule_ids"`
	Match      Match    `json:"match"`
	ValidFrom  string   `json:"valid_from,omitempty"`
	ValidUntil string   `json:"valid_until,omitempty"`
}
type Config struct {
	SchemaVersion string   `json:"schema_version"`
	Policies      []Policy `json:"policies"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("context policy decode: %w", err)
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.SchemaVersion != "1.0" {
		return fmt.Errorf("context policy schema_version must be 1.0")
	}
	if len(c.Policies) > 200 {
		return fmt.Errorf("maximum 200 context policies")
	}
	seen := map[string]bool{}
	idRE := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,79}$`)
	ruleRE := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, p := range c.Policies {
		if !idRE.MatchString(p.ID) || seen[p.ID] {
			return fmt.Errorf("invalid or duplicate context policy id %q", p.ID)
		}
		seen[p.ID] = true
		if p.Decision != "approved" && p.Decision != "elevate" {
			return fmt.Errorf("policy %s: invalid decision %q", p.ID, p.Decision)
		}
		if strings.TrimSpace(p.Reason) == "" || len(p.RuleIDs) == 0 {
			return fmt.Errorf("policy %s: nonempty reason and rule_ids required", p.ID)
		}
		for _, r := range p.RuleIDs {
			if !ruleRE.MatchString(r) {
				return fmt.Errorf("policy %s: invalid rule id %q", p.ID, r)
			}
		}
		if p.Match.DestinationCIDR != "" {
			if _, err := netip.ParsePrefix(p.Match.DestinationCIDR); err != nil {
				return fmt.Errorf("policy %s: destination_cidr: %w", p.ID, err)
			}
		}
		if (p.ValidFrom == "") != (p.ValidUntil == "") {
			return fmt.Errorf("policy %s: both valid_from and valid_until required together", p.ID)
		}
		if p.ValidFrom != "" {
			f, e1 := time.Parse(time.RFC3339, p.ValidFrom)
			u, e2 := time.Parse(time.RFC3339, p.ValidUntil)
			if e1 != nil || e2 != nil || !f.Before(u) {
				return fmt.Errorf("policy %s: invalid UTC time window", p.ID)
			}
		}
		if p.Decision == "approved" {
			// Never allow a blanket rule/namespace approval. Each approved
			// policy needs an independently scoped identity or unique command
			// discriminator. This does NOT verify operator authorization.
			m := p.Match
			strong := m.PodUID != "" || (m.Namespace != "" && m.Pod != "") ||
				(m.Namespace != "" && m.AuditName != "" && m.AuditUser != "") ||
				(m.Namespace != "" && m.ProcessBinary != "" && m.ArgumentsContains != "")
			if !strong {
				return fmt.Errorf("policy %s: approved requires pod_uid, namespace+pod, namespace+audit_name+audit_user, or namespace+process_binary+arguments_contains", p.ID)
			}
		}
	}
	return nil
}

func baseScore(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 25
	case "medium":
		return 50
	case "high":
		return 75
	case "critical":
		return 95
	default:
		return 75
	}
}
func level(score int) string {
	switch {
	case score < 30:
		return "low"
	case score < 60:
		return "medium"
	case score < 85:
		return "high"
	default:
		return "critical"
	}
}
func has(a []string, v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}
func matchesEventSpecific(m Match, e model.SecurityEvent) bool {
	if m.AuditUser != "" && (e.Audit == nil || e.Audit.User != m.AuditUser) {
		return false
	}
	if m.AuditResource != "" && (e.Audit == nil || e.Audit.Resource != m.AuditResource) {
		return false
	}
	if m.AuditName != "" && (e.Audit == nil || e.Audit.Name != m.AuditName) {
		return false
	}
	if m.ProcessBinary != "" && e.Process.Binary != m.ProcessBinary {
		return false
	}
	if m.ArgumentsContains != "" && !strings.Contains(e.Process.Arguments, m.ArgumentsContains) {
		return false
	}
	if m.FilePathPrefix != "" && (e.File == nil || !strings.HasPrefix(e.File.Path, m.FilePathPrefix)) {
		return false
	}
	if m.DestinationCIDR != "" {
		if e.Network == nil {
			return false
		}
		addr, err := netip.ParseAddr(e.Network.DestinationIP)
		if err != nil {
			return false
		}
		cidr, _ := netip.ParsePrefix(m.DestinationCIDR)
		if !cidr.Contains(addr) {
			return false
		}
	}
	return true
}
func (p Policy) matches(a model.SecurityAlert, events []model.SecurityEvent) bool {
	if !p.Enabled || !has(p.RuleIDs, a.RuleID) || len(events) == 0 {
		return false
	}
	m := p.Match
	// A context policy cannot approve a partial correlation: every evidence
	// record must share any declared scope, and the full evidence set must exist.
	for _, e := range events {
		if m.Cluster != "" && (e.Sensor == nil || e.Sensor.Cluster != m.Cluster) {
			return false
		}
		if m.Namespace != "" && (e.Kubernetes == nil || e.Kubernetes.Namespace != m.Namespace) {
			return false
		}
		if m.Pod != "" && (e.Kubernetes == nil || e.Kubernetes.Pod != m.Pod) {
			return false
		}
		if m.PodUID != "" && (e.Kubernetes == nil || e.Kubernetes.PodUID != m.PodUID) {
			return false
		}
	}
	eventSpecific := m.AuditUser != "" || m.AuditResource != "" || m.AuditName != "" || m.ProcessBinary != "" || m.ArgumentsContains != "" || m.FilePathPrefix != "" || m.DestinationCIDR != ""
	if eventSpecific {
		ok := false
		for _, e := range events {
			if matchesEventSpecific(m, e) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if p.ValidFrom != "" {
		from, _ := time.Parse(time.RFC3339, p.ValidFrom)
		until, _ := time.Parse(time.RFC3339, p.ValidUntil)
		for _, e := range events {
			at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil || at.Before(from) || !at.Before(until) {
				return false
			}
		}
	}
	return true
}

// Assess returns a triage recommendation, not a verified security verdict.
// complete=false means not all alert evidence could be resolved. Approved
// policies MUST NOT match in this situation.
func (c Config) Assess(a model.SecurityAlert, events []model.SecurityEvent, complete bool) model.ContextAssessment {
	risk := baseScore(a.Severity)
	v := model.ContextAssessment{Decision: "unmatched", TriageAction: "review", OriginalSeverity: a.Severity, RiskScore: risk, RiskLevel: level(risk), EffectiveSeverity: level(risk), EvidenceComplete: complete, Explanation: "No matching context policy; original rule alert retained"}
	if !complete {
		v.Decision = "incomplete_evidence"
		v.Explanation = "Not all related events available; context approval refused"
		return v
	}
	for _, p := range c.Policies {
		if !p.matches(a, events) {
			continue
		}
		v.PolicyID = p.ID
		v.Decision = p.Decision
		v.Explanation = p.Reason
		if p.Decision == "approved" {
			v.TriageAction = "approved"
			v.RiskScore = 20
		} else {
			v.RiskScore += 20
			if v.RiskScore > 100 {
				v.RiskScore = 100
			}
		}
		v.RiskLevel = level(v.RiskScore)
		v.EffectiveSeverity = v.RiskLevel
		break
	}
	return v
}
