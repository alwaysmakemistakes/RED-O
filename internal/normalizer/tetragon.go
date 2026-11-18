package normalizer

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"runtime-detector/internal/model"
)

// ErrUnsupportedEvent is expected for valid telemetry not yet supported by V1.
var ErrUnsupportedEvent = errors.New("unsupported Tetragon event type")

// The source schema deliberately covers only fields used by the current
// normalizer. json.Unmarshal ignores additional Tetragon fields.
type envelope struct {
	ProcessExit *struct {
		Process sourceProcess `json:"process"`
		Parent  sourceProcess `json:"parent"`
		Signal  string        `json:"signal"`
		Status  *int64        `json:"status"`
	} `json:"process_exit"`
	ProcessKprobe *struct {
		Process      sourceProcess     `json:"process"`
		Parent       sourceProcess     `json:"parent"`
		FunctionName string            `json:"function_name"`
		PolicyName   string            `json:"policy_name"`
		Args         []json.RawMessage `json:"args"`
	} `json:"process_kprobe"`
	ProcessExec *struct {
		Process sourceProcess `json:"process"`
		Parent  sourceProcess `json:"parent"`
	} `json:"process_exec"`
	AuditKind   string `json:"kind"`
	AuditID     string `json:"auditID"`
	AuditStage  string `json:"stage"`
	AuditVerb   string `json:"verb"`
	AuditObject struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Name        string `json:"name"`
		Namespace   string `json:"namespace"`
	} `json:"objectRef"`
	AuditUser struct {
		Username string `json:"username"`
	} `json:"user"`
	AuditStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	AuditStageTimestamp string `json:"stageTimestamp"`
	NodeName            string `json:"node_name"`
	Time                string `json:"time"`
}

type sourceProcess struct {
	ExecID           string `json:"exec_id"`
	ParentExecID     string `json:"parent_exec_id"`
	PID              uint32 `json:"pid"`
	UID              uint32 `json:"uid"`
	Binary           string `json:"binary"`
	Arguments        string `json:"arguments"`
	BinaryProperties struct {
		PrivilegesChanged []string `json:"privileges_changed"`
	} `json:"binary_properties"`
	CWD string     `json:"cwd"`
	Pod *sourcePod `json:"pod"`
}

type sourcePod struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
	Workload     string `json:"workload"`
	WorkloadKind string `json:"workload_kind"`
	Container    struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Image struct {
			Name string `json:"name"`
		} `json:"image"`
	} `json:"container"`
}

// Normalize maps supported Tetragon envelopes to detector SecurityEvent.
// Unknown hooks are preserved as kernel.hook rather than mislabelled file/network events.
func Normalize(raw []byte) (model.SecurityEvent, error) {
	var src envelope
	if err := json.Unmarshal(raw, &src); err != nil {
		return model.SecurityEvent{}, fmt.Errorf("invalid JSON: %w", err)
	}
	// Kubernetes API audit is an independent control-plane source. A request
	// must reach ResponseComplete with a 2xx status to count as successful.
	if src.AuditKind == "Event" && src.AuditID != "" {
		if src.AuditStage != "ResponseComplete" {
			return model.SecurityEvent{}, ErrUnsupportedEvent
		}
		t := src.AuditStageTimestamp
		if _, err := time.Parse(time.RFC3339Nano, t); err != nil {
			return model.SecurityEvent{}, fmt.Errorf("invalid audit timestamp: %w", err)
		}
		id, err := newUUIDv4()
		if err != nil {
			return model.SecurityEvent{}, err
		}
		return model.SecurityEvent{
			SchemaVersion: "1.1", EventID: id, EventType: "k8s.audit", Timestamp: t, Source: "kubernetes-audit",
			Process:    model.Process{Binary: "kube-apiserver"},
			Kubernetes: &model.Kubernetes{Namespace: src.AuditObject.Namespace, Pod: src.AuditObject.Name},
			Audit: &model.Audit{Verb: src.AuditVerb, Resource: src.AuditObject.Resource, Subresource: src.AuditObject.Subresource,
				Name: src.AuditObject.Name, User: src.AuditUser.Username, ResponseCode: src.AuditStatus.Code, Stage: src.AuditStage},
		}, nil
	}
	if _, err := time.Parse(time.RFC3339Nano, src.Time); err != nil {
		return model.SecurityEvent{}, fmt.Errorf("invalid or missing event time: %w", err)
	}
	var proc sourceProcess
	var parent sourceProcess
	var typ string
	var policy, fn string
	var args []json.RawMessage
	switch {
	case src.ProcessExec != nil:
		proc = src.ProcessExec.Process
		parent = src.ProcessExec.Parent
		typ = "process.exec"
		if strings.TrimSpace(proc.Binary) == "" {
			return model.SecurityEvent{}, errors.New("process_exec missing binary")
		}
	case src.ProcessExit != nil:
		proc = src.ProcessExit.Process
		parent = src.ProcessExit.Parent
		typ = "process.exit"
	case src.ProcessKprobe != nil:
		proc = src.ProcessKprobe.Process
		parent = src.ProcessKprobe.Parent
		policy = src.ProcessKprobe.PolicyName
		fn = src.ProcessKprobe.FunctionName
		args = src.ProcessKprobe.Args
		switch {
		case strings.Contains(fn, "security_file_permission") || strings.Contains(fn, "security_file_open") || strings.Contains(fn, "security_path_truncate") || strings.Contains(fn, "sys_openat"):
			typ = "file.access"
		case strings.Contains(fn, "tcp_connect") || strings.Contains(fn, "security_socket_connect"):
			typ = "network.connect"
		default:
			typ = "kernel.hook"
		}
	default:
		return model.SecurityEvent{}, ErrUnsupportedEvent
	}
	id, err := newUUIDv4()
	if err != nil {
		return model.SecurityEvent{}, fmt.Errorf("generate UUID: %w", err)
	}
	out := model.SecurityEvent{SchemaVersion: "1.1", EventID: id, EventType: typ, Timestamp: src.Time, Source: "tetragon", Node: src.NodeName, Policy: policy, Function: fn, Args: args, Process: model.Process{ExecID: proc.ExecID, ParentExecID: proc.ParentExecID, PID: proc.PID, UID: proc.UID, Binary: proc.Binary, Arguments: proc.Arguments, PrivilegesChanged: proc.BinaryProperties.PrivilegesChanged, CWD: proc.CWD, ParentBinary: parent.Binary}}
	if proc.Pod != nil {
		out.Kubernetes = &model.Kubernetes{Namespace: proc.Pod.Namespace, Pod: proc.Pod.Name, PodUID: proc.Pod.UID, Container: proc.Pod.Container.Name, ContainerID: proc.Pod.Container.ID, Image: proc.Pod.Container.Image.Name, Workload: proc.Pod.Workload, WorkloadKind: proc.Pod.WorkloadKind}
	}
	if src.ProcessExit != nil {
		out.Exit = &model.Exit{Signal: src.ProcessExit.Signal, Status: src.ProcessExit.Status}
	}
	if typ == "file.access" {
		out.File = &model.File{Operation: fn}
		if len(args) > 0 {
			out.File.Path = extractFilePath(args[0])
		}
	}
	if typ == "network.connect" {
		out.Network = extractNetwork(args)
	}
	return out, nil
}
func extractFilePath(raw json.RawMessage) string {
	var v struct {
		File struct {
			Path string `json:"path"`
		} `json:"file_arg"`
		Path   string `json:"path_arg"`
		String string `json:"string_arg"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	if v.File.Path != "" {
		return v.File.Path
	}
	if v.Path != "" {
		return v.Path
	}
	return v.String
}
func extractNetwork(args []json.RawMessage) *model.Network {
	n := &model.Network{}
	for _, raw := range args {
		var v struct {
			Sock *struct {
				Family   string `json:"family"`
				Protocol string `json:"protocol"`
				Saddr    string `json:"saddr"`
				Sport    uint32 `json:"sport"`
				Daddr    string `json:"daddr"`
				Dport    uint32 `json:"dport"`
			} `json:"sock_arg"`
		}
		if json.Unmarshal(raw, &v) == nil && v.Sock != nil {
			n.Family = v.Sock.Family
			n.Protocol = v.Sock.Protocol
			n.SourceIP = v.Sock.Saddr
			n.SourcePort = v.Sock.Sport
			n.DestinationIP = v.Sock.Daddr
			n.DestinationPort = v.Sock.Dport
			break
		}
	}
	return n
}

// newUUIDv4 creates a random RFC 4122 UUID using the standard library only.
// UUIDs identify normalized records; Tetragon exec_id remains unchanged.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
