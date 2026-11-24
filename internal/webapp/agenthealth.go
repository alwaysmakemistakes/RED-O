package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type clusterReader func(context.Context, ...string) ([]byte, error)

type podList struct {
	Items []struct {
		Metadata struct {
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			Phase      string `json:"phase"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			ContainerStatuses []struct {
				Name         string `json:"name"`
				Ready        bool   `json:"ready"`
				RestartCount int    `json:"restartCount"`
				State        struct {
					Running *struct {
						StartedAt string `json:"startedAt"`
					} `json:"running"`
					Waiting *struct {
						Reason string `json:"reason"`
					} `json:"waiting"`
					Terminated *struct {
						Reason string `json:"reason"`
					} `json:"terminated"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}
type nodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}
type agentHealth struct {
	Node           string `json:"node"`
	NodeReady      bool   `json:"node_ready"`
	Pod            string `json:"pod"`
	Phase          string `json:"phase"`
	Ready          bool   `json:"ready"`
	ContainerReady bool   `json:"container_ready"`
	Restarts       int    `json:"restarts"`
	StartedAt      string `json:"started_at,omitempty"`
	Status         string `json:"status"`
	Detail         string `json:"detail"`
}

func kubectlReader(ctx context.Context, args ...string) ([]byte, error) {
	binary := "kubectl"
	if _, err := exec.LookPath(binary); err != nil {
		binary = "k3s"
		args = append([]string{"kubectl"}, args...)
	}
	return exec.CommandContext(ctx, binary, args...).Output()
}
func readyCondition(conditions []struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}, name string) bool {
	for _, c := range conditions {
		if c.Type == name {
			return c.Status == "True"
		}
	}
	return false
}
func getAgentHealth(ctx context.Context, reader clusterReader, namespace string) ([]agentHealth, error) {
	podsRaw, err := reader(ctx, "-n", namespace, "get", "pods", "-l", "app.kubernetes.io/name=tetragon", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("get Tetragon Pods: %w", err)
	}
	nodesRaw, err := reader(ctx, "get", "nodes", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("get Kubernetes Nodes: %w", err)
	}
	var pods podList
	var nodes nodeList
	if err = json.Unmarshal(podsRaw, &pods); err != nil {
		return nil, fmt.Errorf("decode pods: %w", err)
	}
	if err = json.Unmarshal(nodesRaw, &nodes); err != nil {
		return nil, fmt.Errorf("decode nodes: %w", err)
	}
	result := []agentHealth{}
	byNode := map[string][]int{}
	for _, p := range pods.Items {
		a := agentHealth{Node: p.Spec.NodeName, Pod: p.Metadata.Name, Phase: p.Status.Phase, Status: "offline", Detail: "Tetragon Pod not ready"}
		a.Ready = readyCondition(p.Status.Conditions, "Ready")
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == "tetragon" {
				a.ContainerReady = c.Ready
				a.Restarts = c.RestartCount
				if c.State.Running != nil {
					a.StartedAt = c.State.Running.StartedAt
				}
				if c.State.Waiting != nil {
					a.Detail = "Tetragon waiting: " + c.State.Waiting.Reason
				}
				if c.State.Terminated != nil {
					a.Detail = "Tetragon terminated: " + c.State.Terminated.Reason
				}
			}
		}
		if a.Ready && a.ContainerReady && a.Phase == "Running" {
			a.Status = "online"
			a.Detail = "Pod and Tetragon container ready"
		}
		result = append(result, a)
		byNode[a.Node] = append(byNode[a.Node], len(result)-1)
	}
	for _, n := range nodes.Items {
		ready := readyCondition(n.Status.Conditions, "Ready")
		indices := byNode[n.Metadata.Name]
		if len(indices) == 0 {
			result = append(result, agentHealth{Node: n.Metadata.Name, NodeReady: ready, Status: "missing", Detail: "No Tetragon agent Pod scheduled on this node"})
			continue
		}
		for _, i := range indices {
			result[i].NodeReady = ready
			if !ready {
				result[i].Status = "degraded"
				result[i].Detail = "Kubernetes Node not Ready"
			}
		}
	}
	for i := range result {
		if strings.TrimSpace(result[i].Node) == "" {
			result[i].Detail = "Agent Pod not scheduled"
		}
	}
	return result, nil
}
