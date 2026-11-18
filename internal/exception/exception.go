package exception

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime-detector/internal/model"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	ID        string `json:"id"`
	RuleID    string `json:"rule_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod,omitempty"`
	Field     string `json:"field,omitempty"`
	Value     string `json:"value,omitempty"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

func (e Entry) Valid() error {
	return e.validate(true)
}

func (e Entry) validate(checkExpiry bool) error {
	if e.ID == "" || e.RuleID == "" || e.Namespace == "" || strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("id, rule_id, namespace and reason are required")
	}
	if e.Field != "" {
		if !AllowedField(e.Field) || e.Value == "" {
			return fmt.Errorf("unsupported exception field or empty value")
		}
	} else if e.Value != "" {
		return fmt.Errorf("value requires field")
	}
	if e.ExpiresAt == "" {
		return fmt.Errorf("expires_at required")
	}
	expiry, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil {
		return err
	}
	if checkExpiry && (!expiry.After(time.Now()) || expiry.After(time.Now().Add(31*24*time.Hour))) {
		return fmt.Errorf("expiry must be in next 30 days")
	}
	return nil
}
func Read(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err = json.Unmarshal(data, &es); err != nil {
		return nil, err
	}
	return es, nil
}
func Write(path string, es []Entry) error {
	for _, e := range es {
		if err := e.validate(false); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".exceptions-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func AllowedField(field string) bool {
	switch field {
	case "process.binary", "process.uid", "file.path", "network.destination_ip", "network.destination_port", "event_type", "kubernetes.container_id", "kubernetes.pod":
		return true
	}
	return false
}
func EventField(e model.SecurityEvent, field string) string {
	switch field {
	case "event_type":
		return e.EventType
	case "process.binary":
		return e.Process.Binary
	case "process.uid":
		return fmt.Sprint(e.Process.UID)
	case "file.path":
		if e.File != nil {
			return e.File.Path
		}
	case "network.destination_ip":
		if e.Network != nil {
			return e.Network.DestinationIP
		}
	case "network.destination_port":
		if e.Network != nil {
			return fmt.Sprint(e.Network.DestinationPort)
		}
	case "kubernetes.container_id":
		if e.Kubernetes != nil {
			return e.Kubernetes.ContainerID
		}
	case "kubernetes.pod":
		if e.Kubernetes != nil {
			return e.Kubernetes.Pod
		}
	}
	return ""
}
func SuppressedWithEvents(es []Entry, a model.SecurityAlert, events []model.SecurityEvent, now time.Time) bool {
	if a.Kubernetes == nil {
		return false
	}
	for _, e := range es {
		if !e.Enabled || e.RuleID != a.RuleID || e.Namespace != a.Kubernetes.Namespace {
			continue
		}
		if e.Pod != "" && e.Pod != a.Kubernetes.Pod {
			continue
		}
		if e.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, e.ExpiresAt)
			if err != nil || !now.Before(t) {
				continue
			}
		}
		if e.Field != "" {
			matched := false
			for _, ev := range events {
				if EventField(ev, e.Field) == e.Value {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return true
	}
	return false
}
func Suppressed(es []Entry, a model.SecurityAlert, now time.Time) bool {
	return SuppressedWithEvents(es, a, nil, now)
}

type Cache struct {
	mu      sync.Mutex
	path    string
	mod     time.Time
	entries []Entry
	checked time.Time
}

func NewCache(path string) *Cache                      { return &Cache{path: path} }
func (c *Cache) Suppressed(a model.SecurityAlert) bool { return c.SuppressedWithEvents(a, nil) }
func (c *Cache) SuppressedWithEvents(a model.SecurityAlert, events []model.SecurityEvent) bool {
	if c == nil || c.path == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Sub(c.checked) > time.Second {
		c.checked = now
		st, err := os.Stat(c.path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("exceptions: stat %s: %v", c.path, err)
			}
		} else if !st.ModTime().Equal(c.mod) || c.entries == nil {
			entries, e := Read(c.path)
			if e != nil {
				log.Printf("exceptions: unable to reload %s: %v", c.path, e)
			} else {
				c.entries = entries
				c.mod = st.ModTime()
				log.Printf("exceptions: loaded %d entries from %s", len(entries), c.path)
			}
		}
	}
	return SuppressedWithEvents(c.entries, a, events, now)
}
