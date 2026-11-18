package webapp

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestAgentHealth(t *testing.T) {
	pods := `{"items":[{"metadata":{"name":"tetragon-1"},"spec":{"nodeName":"main"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":"tetragon","ready":true,"restartCount":2,"state":{"running":{"startedAt":"2026-10-20T18:00:00Z"}}}]}},{"metadata":{"name":"tetragon-2"},"spec":{"nodeName":"worker"},"status":{"phase":"Pending","conditions":[{"type":"Ready","status":"False"}],"containerStatuses":[]}}]}`
	nodes := `{"items":[{"metadata":{"name":"main"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"worker"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"missing"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
	mock := func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "get pods") {
			return []byte(pods), nil
		}
		return []byte(nodes), nil
	}
	got, err := getAgentHealth(context.Background(), mock, "kube-system")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Status != "online" || got[0].Restarts != 2 || got[1].Status != "offline" || got[2].Status != "missing" {
		t.Fatalf("unexpected: %+v", got)
	}
}
func TestAgentHealthFailure(t *testing.T) {
	_, err := getAgentHealth(context.Background(), func(context.Context, ...string) ([]byte, error) { return nil, fmt.Errorf("api denied") }, "kube-system")
	if err == nil {
		t.Fatal("expected failure")
	}
}
