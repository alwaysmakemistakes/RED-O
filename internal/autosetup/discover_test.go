package autosetup

import (
	"context"
	"os"
	"path/filepath"
	"runtime-detector/internal/multisensor"
	"strings"
	"testing"
)

func TestTetraDiscoveryExcludesOperatorAndChoosesNodes(t *testing.T) {
	data := `{"items":[{"metadata":{"name":"tetragon-a","namespace":"kube-system"},"spec":{"nodeName":"main","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}},{"metadata":{"name":"tetragon-operator-abc","namespace":"kube-system"},"spec":{"nodeName":"main","containers":[{"name":"operator"}]},"status":{"phase":"Running"}},{"metadata":{"name":"tetragon-b","namespace":"kube-system"},"spec":{"nodeName":"worker","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}}]}`
	pods, err := ParseTetragonPods([]byte(data), "")
	if err != nil || len(pods) != 2 {
		t.Fatalf("pods=%v err=%v", pods, err)
	}
	if pods[0].Name != "tetragon-a" || pods[1].Name != "tetragon-b" {
		t.Fatalf("wrong pods: %v", pods)
	}
	c := multisensor.Config{SchemaVersion: "1.0", Sensors: []multisensor.Sensor{{ID: "tetra-main", Type: "tetra", Cluster: "lab", Namespace: "kube-system", Pod: "tetragon-a", Node: "main"}}}
	if err := c.Validate(); err != nil {
		t.Fatalf("single Tetragon sensor must be allowed: %v", err)
	}
}
func TestTetraDiscoveryRejectsAmbiguous(t *testing.T) {
	data := `{"items":[{"metadata":{"name":"one","namespace":"a"},"spec":{"nodeName":"n","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}},{"metadata":{"name":"two","namespace":"b"},"spec":{"nodeName":"n","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}}]}`
	_, err := ParseTetragonPods([]byte(data), "")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatal(err)
	}
}

// A K3s control-plane VM can have only the k3s CLI, without a separate kubectl.
func TestDiscoverViaK3sCLIAndOptionalAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k3s")
	script := `#!/bin/sh
case "$*" in
  'kubectl config current-context') echo test-k3s ;;
  'kubectl get pods --all-namespaces -o json') printf '%s\n' '{"items":[{"metadata":{"name":"tetragon-a","namespace":"kube-system"},"spec":{"nodeName":"test-node","containers":[{"name":"tetragon"}]},"status":{"phase":"Running","containerStatuses":[{"name":"tetragon","ready":true}]}}]}'
    ;;
  *) echo "Unexpected: $*" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	d, err := Discover(context.Background(), Options{AuditMode: "off"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Config.Sensors) != 1 || d.Config.Sensors[0].Kubectl != "k3s" || d.Config.Sensors[0].Pod != "tetragon-a" {
		t.Fatalf("k3s discovery: %+v", d.Config)
	}
	audit := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(audit, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	d, err = Discover(context.Background(), Options{AuditMode: "required", AuditPath: audit})
	if err != nil || len(d.Config.Sensors) != 2 || !d.AuditIncluded {
		t.Fatalf("k3s audit discovery: %+v err=%v", d, err)
	}
}
