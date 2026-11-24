// Package multisensor collects independent, explicitly named telemetry streams.
// Every source runs independently and is bounded by a shared backpressure queue.
package multisensor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Sensor struct {
	ID             string `json:"id"`
	Type           string `json:"type"` // tetra, audit, or jsonl
	Cluster        string `json:"cluster"`
	Node           string `json:"node,omitempty"`
	Kubectl        string `json:"kubectl,omitempty"`
	Context        string `json:"context,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	Container      string `json:"container,omitempty"`
	EventNamespace string `json:"event_namespace,omitempty"`
	Path           string `json:"path,omitempty"`
	FromStart      bool   `json:"from_start,omitempty"`
}

type Config struct {
	SchemaVersion string   `json:"schema_version"`
	Sensors       []Sensor `json:"sensors"`
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse sensors: %w", err)
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.SchemaVersion != "1.0" {
		return fmt.Errorf("sensors schema_version must be 1.0")
	}
	if len(c.Sensors) < 1 || len(c.Sensors) > 64 {
		return fmt.Errorf("multi mode requires between 1 and 64 sensors")
	}
	seen := map[string]bool{}
	targets := map[string]string{}
	for _, s := range c.Sensors {
		if !validID.MatchString(s.ID) || seen[s.ID] {
			return fmt.Errorf("invalid or duplicated sensor id %q", s.ID)
		}
		seen[s.ID] = true
		if !validID.MatchString(s.Cluster) {
			return fmt.Errorf("sensor %s: cluster identifier required (letters, numbers, underscore, dot, dash)", s.ID)
		}
		if s.Node != "" && !validID.MatchString(s.Node) {
			return fmt.Errorf("sensor %s: invalid node name", s.ID)
		}
		for _, value := range []string{s.Pod, s.Namespace, s.Container, s.Context, s.EventNamespace} {
			if strings.HasPrefix(value, "-") {
				return fmt.Errorf("sensor %s: invalid Kubernetes selector", s.ID)
			}
		}
		key := ""
		switch s.Type {
		case "tetra":
			if s.Pod == "" || s.Namespace == "" {
				return fmt.Errorf("sensor %s: Tetragon requires explicit pod and namespace; daemonset selection is ambiguous", s.ID)
			}
			if strings.Contains(s.Pod, "/") {
				return fmt.Errorf("sensor %s: use the exact Tetragon pod name", s.ID)
			}
			if s.Path != "" {
				return fmt.Errorf("sensor %s: Tetragon does not use path", s.ID)
			}
			container := s.Container
			if container == "" {
				container = "tetragon"
			}
			key = "tetra|" + s.Context + "|" + s.Namespace + "|" + s.Pod + "|" + container
		case "audit", "jsonl":
			if s.Path == "" || s.Path == "-" {
				return fmt.Errorf("sensor %s: nonempty file path required", s.ID)
			}
			path, err := filepath.Abs(s.Path)
			if err != nil {
				return fmt.Errorf("sensor %s: canonicalize path: %w", s.ID, err)
			}
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				path = resolved
			}
			key = "file|" + path
		default:
			return fmt.Errorf("sensor %s: unsupported type %q", s.ID, s.Type)
		}
		if first, ok := targets[key]; ok {
			return fmt.Errorf("sensors %s and %s share input %q (would duplicate ingestion)", first, s.ID, key)
		}
		targets[key] = s.ID
	}
	return nil
}

// Record carries receipt time before any normalization or waiting for other sensors.
type Record struct {
	Sensor     Sensor
	Data       []byte
	ReceivedAt time.Time
}
