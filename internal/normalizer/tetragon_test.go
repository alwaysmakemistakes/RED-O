package normalizer

import (
	"encoding/json"
	"errors"
	"regexp"
	"testing"
)

func TestNormalizeExec(t *testing.T) {
	raw := []byte(`{"process_exec":{"process":{"exec_id":"id1","parent_exec_id":"p1","pid":29130,"uid":0,"binary":"/bin/sh","arguments":"-c id","pod":{"namespace":"security-lab","name":"ebpf-test","uid":"pod1","container":{"id":"containerd://abc","name":"ebpf-test","image":{"name":"busybox:1.36"}}}},"parent":{"binary":"/usr/bin/containerd-shim-runc-v2"}},"time":"2026-10-17T14:29:03.675515319Z","node_name":"main"}`)
	got, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventType != "process.exec" || got.Process.Binary != "/bin/sh" || got.Process.UID != 0 {
		t.Fatalf("unexpected process: %+v", got)
	}
	if got.Kubernetes == nil || got.Kubernetes.Namespace != "security-lab" || got.Kubernetes.ContainerID != "containerd://abc" {
		t.Fatalf("unexpected kubernetes context: %+v", got.Kubernetes)
	}
	if got.Timestamp != "2026-10-17T14:29:03.675515319Z" {
		t.Fatalf("lost timestamp precision: %s", got.Timestamp)
	}
}

func TestUnsupported(t *testing.T) {
	_, err := Normalize([]byte(`{"process_loader":{"process":{"pid":1}},"time":"2026-10-17T14:29:03Z"}`))
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatalf("expected unsupported, got %v", err)
	}
}

func TestRejectMissingTime(t *testing.T) {
	_, err := Normalize([]byte(`{"process_exec":{"process":{"binary":"/bin/sh"}}}`))
	if err == nil {
		t.Fatal("missing time accepted")
	}
}

func TestEventIDsAreUniqueAndUUIDv4(t *testing.T) {
	raw := []byte(`{"process_exec":{"process":{"exec_id":"upstream-exec","binary":"/bin/sh"}},"time":"2026-10-17T14:29:03Z"}`)
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	ids := make(map[string]struct{})
	for i := 0; i < 200; i++ {
		ev, err := Normalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(ev.EventID) {
			t.Fatalf("invalid UUID v4: %q", ev.EventID)
		}
		if _, exists := ids[ev.EventID]; exists {
			t.Fatalf("repeated UUID: %q", ev.EventID)
		}
		ids[ev.EventID] = struct{}{}
		if ev.Process.ExecID != "upstream-exec" {
			t.Fatal("Tetragon exec_id changed")
		}
		serialized, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(serialized, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["event_id"]; !ok {
			t.Fatal("event_id missing from JSON")
		}
	}
}
