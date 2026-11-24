package detection

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"runtime-detector/internal/model"
)

type Engine struct {
	rules     []Rule
	seen      map[string]map[string]networkEvidence
	lastAlert map[string]time.Time
}

func New(c Config) (*Engine, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	rules := append([]Rule(nil), c.Rules...)
	for i := range rules {
		if rules[i].BinaryRegex != "" {
			rules[i].compiledBinary = regexp.MustCompile(rules[i].BinaryRegex)
		}
		if rules[i].ArgumentsRegex != "" {
			rules[i].compiledArguments = regexp.MustCompile(rules[i].ArgumentsRegex)
		}
		if rules[i].PathRegex != "" {
			rules[i].compiledPath = regexp.MustCompile(rules[i].PathRegex)
		}
		for _, s := range rules[i].DestinationCIDRs {
			p, _ := netip.ParsePrefix(s)
			rules[i].compiledCIDRs = append(rules[i].compiledCIDRs, p)
		}
	}
	return &Engine{rules: rules, seen: make(map[string]map[string]networkEvidence), lastAlert: make(map[string]time.Time)}, nil
}
func (e *Engine) Evaluate(event model.SecurityEvent) ([]model.SecurityAlert, error) {
	var alerts []model.SecurityAlert
	if event.EventID == "" {
		return nil, fmt.Errorf("event_id missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	at, _ := time.Parse(time.RFC3339Nano, event.Timestamp)
	for _, r := range e.rules {
		if !r.Enabled || !matches(r, event) {
			continue
		}
		var evidence *model.AlertEvidence
		relatedIDs := []string{event.EventID}
		if r.DistinctDestinations > 0 {
			var hit bool
			evidence, relatedIDs, hit = e.distinctHit(r, event, at)
			if !hit {
				continue
			}
		}
		id, err := uuidv4()
		if err != nil {
			return nil, err
		}
		alert := model.SecurityAlert{SchemaVersion: "1.0", AlertID: id, RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Status: "firing", Timestamp: event.Timestamp, DetectedAt: time.Now().UTC().Format(time.RFC3339Nano), Description: r.Description, Reason: reason(r, event), Kubernetes: event.Kubernetes, RelatedEventIDs: relatedIDs, Evidence: evidence}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}
func matches(r Rule, e model.SecurityEvent) bool {
	if e.EventType != r.EventType {
		return false
	}
	ns := ""
	if e.Kubernetes != nil {
		ns = e.Kubernetes.Namespace
	}
	if len(r.NamespaceAllow) > 0 && !contains(r.NamespaceAllow, ns) {
		return false
	}
	if contains(r.NamespaceExclude, ns) {
		return false
	}
	// Within one field, alternatives are OR; between fields conditions are AND.
	if len(r.BinaryIn) > 0 && !contains(r.BinaryIn, e.Process.Binary) {
		return false
	}
	if r.compiledBinary != nil && !r.compiledBinary.MatchString(e.Process.Binary) {
		return false
	}
	if r.compiledArguments != nil && !r.compiledArguments.MatchString(e.Process.Arguments) {
		return false
	}
	if r.PrivilegesRaised {
		raised := false
		for _, change := range e.Process.PrivilegesChanged {
			if strings.HasPrefix(change, "PRIVILEGES_RAISED_") {
				raised = true
				break
			}
		}
		if !raised {
			return false
		}
	}
	if len(r.FunctionIn) > 0 && !contains(r.FunctionIn, e.Function) {
		return false
	}
	if len(r.AuditVerbs)+len(r.AuditResources) > 0 {
		if e.Audit == nil || e.Audit.ResponseCode < 200 || e.Audit.ResponseCode >= 300 || e.Audit.Stage != "ResponseComplete" {
			return false
		}
		if len(r.AuditVerbs) > 0 && !contains(r.AuditVerbs, e.Audit.Verb) {
			return false
		}
		if len(r.AuditResources) > 0 && !contains(r.AuditResources, e.Audit.Resource) {
			return false
		}
		if contains(r.AuditUsersExclude, e.Audit.User) {
			return false
		}
	}
	if len(r.PathIn)+len(r.PathPrefixes) > 0 || r.PathRegex != "" {
		if e.File == nil {
			return false
		}
		matched := contains(r.PathIn, e.File.Path)
		for _, prefix := range r.PathPrefixes {
			if strings.HasPrefix(e.File.Path, prefix) {
				matched = true
			}
		}
		if r.compiledPath != nil && r.compiledPath.MatchString(e.File.Path) {
			matched = true
		}
		if !matched {
			return false
		}
	}
	if len(r.DestinationIPs)+len(r.DestinationPorts)+len(r.DestinationCIDRs) > 0 {
		if e.Network == nil {
			return false
		}
		if len(r.DestinationIPs) > 0 && !contains(r.DestinationIPs, e.Network.DestinationIP) {
			return false
		}
		if len(r.DestinationCIDRs) > 0 {
			ip, err := netip.ParseAddr(e.Network.DestinationIP)
			if err != nil {
				return false
			}
			ok := false
			for _, prefix := range r.compiledCIDRs {
				if prefix.Contains(ip) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
		if len(r.DestinationPorts) > 0 {
			found := false
			for _, p := range r.DestinationPorts {
				if p == e.Network.DestinationPort {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func reason(r Rule, e model.SecurityEvent) string {
	switch e.EventType {
	case "process.exec":
		return fmt.Sprintf("Observed execution of %s (uid=%d)", e.Process.Binary, e.Process.UID)
	case "file.access":
		return fmt.Sprintf("Observed file permission hook for %s; success not established", e.File.Path)
	case "network.connect":
		return fmt.Sprintf("Observed TCP connect attempt to %s:%d; success not established", e.Network.DestinationIP, e.Network.DestinationPort)
	case "k8s.audit":
		return fmt.Sprintf("Kubernetes API audit: user=%s verb=%s resource=%s name=%s code=%d", e.Audit.User, e.Audit.Verb, e.Audit.Resource, e.Audit.Name, e.Audit.ResponseCode)
	default:
		return fmt.Sprintf("Event matched rule %s", r.ID)
	}
}
func uuidv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// networkEvidence stores the latest observation for each destination in the bounded window.
type networkEvidence struct {
	at      time.Time
	eventID string
}

// distinctHit returns every distinct destination's supporting event ID,
// sorted by event time, so trial attribution cannot be based on the final
// threshold event alone. State is bounded by rule config (<=256 destinations).
func (e *Engine) distinctHit(r Rule, ev model.SecurityEvent, now time.Time) (*model.AlertEvidence, []string, bool) {
	if ev.Kubernetes == nil || ev.Kubernetes.ContainerID == "" || ev.Network == nil {
		return nil, nil, false
	}
	cluster := ""
	if ev.Sensor != nil {
		cluster = ev.Sensor.Cluster
	}
	key := r.ID + "|" + cluster + "|" + ev.Node + "|" + ev.Kubernetes.PodUID + "|" + ev.Kubernetes.ContainerID
	window := time.Duration(r.WindowSeconds) * time.Second
	if len(e.seen) > 4096 {
		e.seen = make(map[string]map[string]networkEvidence)
		e.lastAlert = make(map[string]time.Time)
	}
	ips := e.seen[key]
	if ips == nil {
		ips = make(map[string]networkEvidence)
		e.seen[key] = ips
	}
	for ip, obs := range ips {
		if now.Sub(obs.at) > window || now.Before(obs.at) {
			delete(ips, ip)
		}
	}
	ips[ev.Network.DestinationIP] = networkEvidence{at: now, eventID: ev.EventID}
	// Keep the newest N distinct destinations. This preserves the threshold
	// semantics while keeping each container's evidence map bounded.
	for len(ips) > r.DistinctDestinations {
		oldestIP := ""
		var oldest time.Time
		for ip, obs := range ips {
			if oldestIP == "" || obs.at.Before(oldest) || (obs.at.Equal(oldest) && ip < oldestIP) {
				oldestIP, oldest = ip, obs.at
			}
		}
		delete(ips, oldestIP)
	}
	if len(ips) < r.DistinctDestinations {
		return nil, nil, false
	}
	if prev, ok := e.lastAlert[key]; ok && now.Sub(prev) < window && !now.Before(prev) {
		return nil, nil, false
	}
	e.lastAlert[key] = now
	type pair struct {
		ip  string
		obs networkEvidence
	}
	ordered := make([]pair, 0, len(ips))
	for ip, obs := range ips {
		ordered = append(ordered, pair{ip, obs})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].obs.at.Equal(ordered[j].obs.at) {
			return ordered[i].ip < ordered[j].ip
		}
		return ordered[i].obs.at.Before(ordered[j].obs.at)
	})
	// Limit the forensic chain to the configured threshold (the first
	// distinct targets that establish the rule), avoiding unbounded alerts.
	if len(ordered) > r.DistinctDestinations {
		ordered = ordered[:r.DistinctDestinations]
	}
	ids := make([]string, 0, len(ordered))
	destinations := make([]string, 0, len(ordered))
	for _, item := range ordered {
		ids = append(ids, item.obs.eventID)
		destinations = append(destinations, item.ip)
	}
	evidence := &model.AlertEvidence{
		WindowStart:          ordered[0].obs.at.UTC().Format(time.RFC3339Nano),
		WindowEnd:            now.UTC().Format(time.RFC3339Nano),
		WindowSeconds:        r.WindowSeconds,
		DistinctDestinations: len(ordered),
		Threshold:            r.DistinctDestinations,
		DestinationIPs:       destinations,
	}
	return evidence, ids, true
}
