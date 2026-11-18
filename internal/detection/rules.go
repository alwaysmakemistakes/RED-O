package detection

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	Rules []Rule `json:"rules"`
}
type Rule struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Severity             string   `json:"severity"`
	Description          string   `json:"description"`
	EventType            string   `json:"event_type"`
	NamespaceAllow       []string `json:"namespace_allow,omitempty"`
	NamespaceExclude     []string `json:"namespace_exclude,omitempty"`
	BinaryIn             []string `json:"binary_in,omitempty"`
	BinaryRegex          string   `json:"binary_regex,omitempty"`
	ArgumentsRegex       string   `json:"arguments_regex,omitempty"`
	PrivilegesRaised     bool     `json:"privileges_raised,omitempty"`
	DistinctDestinations int      `json:"distinct_destinations,omitempty"`
	WindowSeconds        int      `json:"window_seconds,omitempty"`
	FunctionIn           []string `json:"function_in,omitempty"`
	PathRegex            string   `json:"path_regex,omitempty"`
	DestinationCIDRs     []string `json:"destination_cidrs,omitempty"`
	AuditVerbs           []string `json:"audit_verbs,omitempty"`
	AuditResources       []string `json:"audit_resources,omitempty"`
	AuditUsersExclude    []string `json:"audit_users_exclude,omitempty"`
	compiledBinary       *regexp.Regexp
	compiledArguments    *regexp.Regexp
	compiledPath         *regexp.Regexp
	compiledCIDRs        []netip.Prefix
	PathIn               []string `json:"path_in,omitempty"`
	PathPrefixes         []string `json:"path_prefixes,omitempty"`
	DestinationIPs       []string `json:"destination_ips,omitempty"`
	DestinationPorts     []uint32 `json:"destination_ports,omitempty"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse rule config (JSON/YAML 1.2 JSON subset): %w", err)
	}
	if err = c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func (c Config) Validate() error {
	seen := map[string]bool{}
	validSeverity := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validType := map[string]bool{"process.exec": true, "process.exit": true, "file.access": true, "network.connect": true, "kernel.hook": true, "k8s.audit": true}
	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	for i, r := range c.Rules {
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(r.ID) {
			return fmt.Errorf("rule %d: invalid id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("rule %s: missing name", r.ID)
		}
		if !validSeverity[r.Severity] {
			return fmt.Errorf("rule %s: invalid severity", r.ID)
		}
		if !validType[r.EventType] {
			return fmt.Errorf("rule %s: invalid event_type", r.ID)
		}
		if len(r.BinaryIn)+len(r.BinaryRegex)+len(r.ArgumentsRegex)+boolInt(r.PrivilegesRaised)+len(r.FunctionIn)+len(r.PathIn)+len(r.PathPrefixes)+len(r.PathRegex)+len(r.DestinationIPs)+len(r.DestinationPorts)+len(r.DestinationCIDRs)+len(r.AuditVerbs)+len(r.AuditResources) == 0 {
			return fmt.Errorf("rule %s: missing matching condition", r.ID)
		}
		if (len(r.PathIn)+len(r.PathPrefixes)+len(r.PathRegex) > 0 && r.EventType != "file.access") ||
			(len(r.DestinationIPs)+len(r.DestinationPorts)+len(r.DestinationCIDRs) > 0 && r.EventType != "network.connect") ||
			(len(r.BinaryIn)+len(r.BinaryRegex)+len(r.ArgumentsRegex)+boolInt(r.PrivilegesRaised) > 0 && r.EventType != "process.exec") ||
			(len(r.FunctionIn) > 0 && r.EventType != "kernel.hook") ||
			(len(r.AuditVerbs)+len(r.AuditResources)+len(r.AuditUsersExclude) > 0 && r.EventType != "k8s.audit") {
			return fmt.Errorf("rule %s: conditions incompatible with event_type", r.ID)
		}
		for _, named := range []struct{ name, pattern string }{{"binary_regex", r.BinaryRegex}, {"arguments_regex", r.ArgumentsRegex}, {"path_regex", r.PathRegex}} {
			if named.pattern != "" {
				if _, err := regexp.Compile(named.pattern); err != nil {
					return fmt.Errorf("rule %s: invalid %s: %w", r.ID, named.name, err)
				}
			}
		}
		if r.DistinctDestinations != 0 {
			if r.EventType != "network.connect" || r.DistinctDestinations < 2 || r.DistinctDestinations > 256 || r.WindowSeconds < 1 || r.WindowSeconds > 3600 {
				return fmt.Errorf("rule %s: invalid network distinct destination threshold/window", r.ID)
			}
		} else if r.WindowSeconds != 0 {
			return fmt.Errorf("rule %s: window_seconds requires distinct_destinations", r.ID)
		}
		for _, cidr := range r.DestinationCIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("rule %s: invalid CIDR %q: %w", r.ID, cidr, err)
			}
		}
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
