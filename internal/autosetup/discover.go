// Package autosetup builds a deployable configuration from Kubernetes discovery.
// Discovery is read-only, without jq or hard-coded Tetragon pod names.
package autosetup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"runtime-detector/internal/multisensor"
)

type podList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			NodeName   string `json:"nodeName"`
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name  string `json:"name"`
				Ready bool   `json:"ready"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type Pod struct{ Name, Namespace, Node string }

var safeName = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func sanitise(value string) string {
	value = strings.Trim(safeName.ReplaceAllString(value, "-"), "-._")
	if value == "" {
		return "cluster"
	}
	if len(value) > 60 {
		value = value[:60]
	}
	return value
}

func ParseTetragonPods(payload []byte, namespace string) ([]Pod, error) {
	var list podList
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, fmt.Errorf("parse Kubernetes pod list: %w", err)
	}
	var result []Pod
	perNode := map[string]Pod{}
	for _, p := range list.Items {
		if p.Status.Phase != "Running" || p.Spec.NodeName == "" {
			continue
		}
		if namespace != "" && p.Metadata.Namespace != namespace {
			continue
		}
		hasTetra := false
		for _, c := range p.Spec.Containers {
			if c.Name == "tetragon" {
				hasTetra = true
			}
		}
		if !hasTetra {
			continue
		} // excludes tetragon-operator
		ready := false
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == "tetragon" && s.Ready {
				ready = true
			}
		}
		if !ready {
			continue
		}
		hit := Pod{Name: p.Metadata.Name, Namespace: p.Metadata.Namespace, Node: p.Spec.NodeName}
		if other, found := perNode[hit.Node]; found {
			return nil, fmt.Errorf("ambiguous Tetragon on node %q: %s/%s and %s/%s; use -tetragon-namespace", hit.Node, other.Namespace, other.Name, hit.Namespace, hit.Name)
		}
		perNode[hit.Node] = hit
		result = append(result, hit)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Node < result[j].Node })
	if len(result) == 0 {
		return nil, errors.New("no Ready Tetragon containers found in Running Kubernetes Pods; check kubectl access and Tetragon status")
	}
	return result, nil
}

func command(ctx context.Context, kubectl string, argv ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if filepath.Base(kubectl) == "k3s" {
		argv = append([]string{"kubectl"}, argv...)
	}
	out, err := exec.CommandContext(cctx, kubectl, argv...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl %s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Options are explicitly local: kubeconfig context controls which cluster is queried.
// Audit can be attached only if its log file is readable by the local process.
type Options struct{ Kubectl, Context, Namespace, Cluster, EventNamespace, AuditPath, AuditMode string }

type Discovery struct {
	Config            multisensor.Config
	KubernetesContext string
	AuditIncluded     bool
	Notices           []string
}

func Discover(ctx context.Context, o Options) (Discovery, error) {
	if o.Kubectl == "" || o.Kubectl == "auto" {
		if _, err := exec.LookPath("kubectl"); err == nil {
			o.Kubectl = "kubectl"
		} else if _, err := exec.LookPath("k3s"); err == nil {
			o.Kubectl = "k3s"
		} else {
			return Discovery{}, errors.New("neither kubectl nor k3s executable is available in PATH")
		}
	}
	if o.AuditMode == "" {
		o.AuditMode = "auto"
	}
	if o.AuditMode != "auto" && o.AuditMode != "off" && o.AuditMode != "required" {
		return Discovery{}, fmt.Errorf("invalid audit mode %q (auto|off|required)", o.AuditMode)
	}
	prefix := []string{}
	if o.Context != "" {
		prefix = append(prefix, "--context", o.Context)
	}
	contextName := o.Context
	if contextName == "" {
		b, err := command(ctx, o.Kubectl, "config", "current-context")
		if err != nil {
			return Discovery{}, err
		}
		contextName = strings.TrimSpace(string(b))
	}
	argv := append(append([]string{}, prefix...), "get", "pods", "--all-namespaces", "-o", "json")
	b, err := command(ctx, o.Kubectl, argv...)
	if err != nil {
		return Discovery{}, err
	}
	pods, err := ParseTetragonPods(b, o.Namespace)
	if err != nil {
		return Discovery{}, err
	}
	cluster := sanitise(o.Cluster)
	if o.Cluster == "" {
		cluster = sanitise(contextName)
	}
	result := Discovery{KubernetesContext: contextName, Config: multisensor.Config{SchemaVersion: "1.0"}}
	ids := map[string]bool{}
	for _, p := range pods {
		id := "tetra-" + sanitise(p.Node)
		if len(id) > 64 {
			id = id[:64]
		}
		if ids[id] {
			return Discovery{}, fmt.Errorf("Tetragon node identifier collision for %q", p.Node)
		}
		ids[id] = true
		result.Config.Sensors = append(result.Config.Sensors, multisensor.Sensor{ID: id, Type: "tetra", Cluster: cluster, Node: p.Node, Kubectl: o.Kubectl, Context: o.Context, Namespace: p.Namespace, Pod: p.Name, Container: "tetragon", EventNamespace: o.EventNamespace})
	}
	if o.AuditMode != "off" {
		path := o.AuditPath
		if path == "" {
			for _, candidate := range []string{"/var/lib/rancher/k3s/server/logs/audit.log", "/var/log/kubernetes/audit.log", "/var/log/kube-apiserver/audit.log"} {
				if readableFile(candidate) {
					path = candidate
					break
				}
			}
		}
		if path != "" && readableFile(path) {
			abs, err := filepath.Abs(path)
			if err != nil {
				return Discovery{}, err
			}
			result.Config.Sensors = append(result.Config.Sensors, multisensor.Sensor{ID: "k8s-audit", Type: "audit", Cluster: cluster, Path: abs, FromStart: false})
			result.AuditIncluded = true
		} else if o.AuditMode == "required" {
			return Discovery{}, fmt.Errorf("Kubernetes Audit required but readable audit log not found at %q", path)
		} else {
			result.Notices = append(result.Notices, "Kubernetes Audit log not found locally; starting Tetragon-only. Audit rule R016 needs a configured apiserver audit log.")
		}
	}
	if err := result.Config.Validate(); err != nil {
		return Discovery{}, err
	}
	return result, nil
}
func readableFile(path string) bool {
	stat, err := os.Stat(path)
	if err != nil || !stat.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func Encode(c multisensor.Config) ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
