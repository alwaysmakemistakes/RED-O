package model

import "encoding/json"

// SecurityEvent is the detector's source-independent event representation.
// SchemaVersion makes future changes to the exported JSON explicit.
type SecurityEvent struct {
	SchemaVersion string            `json:"schema_version"`
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	Timestamp     string            `json:"timestamp"`
	ReceivedAt    string            `json:"received_at,omitempty"`
	Sensor        *Sensor           `json:"sensor,omitempty"`
	Source        string            `json:"source"`
	Node          string            `json:"node,omitempty"`
	Process       Process           `json:"process"`
	Kubernetes    *Kubernetes       `json:"kubernetes,omitempty"`
	Policy        string            `json:"policy,omitempty"`
	Function      string            `json:"function,omitempty"`
	File          *File             `json:"file,omitempty"`
	Network       *Network          `json:"network,omitempty"`
	Exit          *Exit             `json:"exit,omitempty"`
	Audit         *Audit            `json:"audit,omitempty"`
	Args          []json.RawMessage `json:"hook_args,omitempty"`
}

type Process struct {
	ExecID            string   `json:"exec_id"`
	ParentExecID      string   `json:"parent_exec_id,omitempty"`
	PID               uint32   `json:"pid"`
	UID               uint32   `json:"uid"`
	Binary            string   `json:"binary"`
	Arguments         string   `json:"arguments,omitempty"`
	PrivilegesChanged []string `json:"privileges_changed,omitempty"`
	CWD               string   `json:"cwd,omitempty"`
	ParentBinary      string   `json:"parent_binary,omitempty"`
}

type Kubernetes struct {
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	PodUID       string `json:"pod_uid,omitempty"`
	Container    string `json:"container,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	Image        string `json:"image,omitempty"`
	Workload     string `json:"workload,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"`
}

// File is a best-effort projection of file-related hook arguments.
type File struct {
	Path      string `json:"path,omitempty"`
	Operation string `json:"operation,omitempty"`
}

// Network is a best-effort projection of a socket argument.
type Network struct {
	Family          string `json:"family,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
}
type Exit struct {
	Signal string `json:"signal,omitempty"`
	Status *int64 `json:"status,omitempty"`
}

// Audit contains Kubernetes API audit metadata (not a kernel/eBPF event).
// It deliberately excludes request and response bodies, which may carry secrets.
type Audit struct {
	Verb         string `json:"verb"`
	Resource     string `json:"resource"`
	Subresource  string `json:"subresource,omitempty"`
	Name         string `json:"name,omitempty"`
	User         string `json:"user,omitempty"`
	ResponseCode int    `json:"response_code"`
	Stage        string `json:"stage"`
}

// Sensor is the authenticated/configured stream origin. It is not inferred
// from untrusted event fields. Cluster scopes correlation across installations.
type Sensor struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Cluster string `json:"cluster"`
	Node    string `json:"node,omitempty"`
}
