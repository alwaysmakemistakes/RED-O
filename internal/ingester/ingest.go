package ingester

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime-detector/internal/clickhouse"
	"runtime-detector/internal/model"
	"runtime-detector/internal/storage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type fileCursor struct {
	Identity string `json:"identity,omitempty"`
	Offset   int64  `json:"offset"`
}
type ingestCheckpoint struct {
	Version int                   `json:"version"`
	Files   map[string]fileCursor `json:"files"`
}

func loadCheckpoint(path string) (*ingestCheckpoint, error) {
	cp := &ingestCheckpoint{Version: 2, Files: map[string]fileCursor{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cp, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, cp); err == nil && cp.Version == 2 && cp.Files != nil {
		return cp, nil
	}
	// Support v0.8.0 legacy checkpoints (path -> integer byte offset).
	legacy := map[string]int64{}
	if err := json.Unmarshal(b, &legacy); err != nil {
		return nil, fmt.Errorf("invalid ingester checkpoint: %w", err)
	}
	cp = &ingestCheckpoint{Version: 2, Files: map[string]fileCursor{}}
	for name, offset := range legacy {
		if offset >= 0 {
			cp.Files[name] = fileCursor{Offset: offset}
		}
	}
	return cp, nil
}
func saveCheckpoint(path string, cp *ingestCheckpoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if d, e := os.Open(filepath.Dir(path)); e == nil {
		defer d.Close()
		return d.Sync()
	}
	return nil
}
func fileIdentity(st os.FileInfo) string {
	if v, ok := st.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(v.Dev), 10) + ":" + strconv.FormatUint(v.Ino, 10)
	}
	return ""
}
func (cp *ingestCheckpoint) position(path, identity string, size int64) fileCursor {
	cur, has := cp.Files[path]
	if has && cur.Identity == identity && cur.Offset <= size {
		return cur
	}
	if identity != "" {
		for _, c := range cp.Files {
			if c.Identity == identity && c.Offset <= size {
				return c
			}
		}
	}
	// Legacy checkpoint has no inode: apply only if a file has not rotated already.
	if has && cur.Identity == "" && cur.Offset <= size {
		return fileCursor{Identity: identity, Offset: cur.Offset}
	}
	return fileCursor{Identity: identity}
}
func ingest(ctx context.Context, db *clickhouse.Client, events, alerts, checkpoint string) {
	cp, err := loadCheckpoint(checkpoint)
	if err != nil {
		log.Printf("FATAL: invalid ingester checkpoint: %v (ingest disabled; restore/repair checkpoint)", err)
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		for _, stream := range []struct{ kind, path string }{{"events", events}, {"alerts", alerts}} {
			if err := ingestStream(ctx, db, stream.kind, stream.path, cp, checkpoint); err != nil {
				log.Printf("ingest %s: %v", stream.kind, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func ingestStream(ctx context.Context, db *clickhouse.Client, kind, path string, cp *ingestCheckpoint, checkpoint string) error {
	parts, err := storage.Segments(path)
	if err != nil {
		return err
	}
	parts = append(parts, path)
	for _, name := range parts {
		if err := ingestPart(ctx, db, kind, name, cp, checkpoint, name != path); err != nil {
			return err
		}
		// Never import a newer segment while an older segment has pending rows.
		if name != path {
			if _, err := os.Stat(name); err == nil {
				return nil
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
func ingestPart(ctx context.Context, db *clickhouse.Client, kind, path string, cp *ingestCheckpoint, checkpoint string, immutable bool) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	ident := fileIdentity(st)
	cur := cp.position(path, ident, st.Size())
	if _, err = f.Seek(cur.Offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReader(f)
	batch := []map[string]any{}
	offset := cur.Offset
	for processed := 0; processed < 1000 && len(batch) < 100; processed++ {
		line, e := r.ReadBytes('\n')
		if e == io.EOF {
			break
		} // Incomplete final record: retry when newline appears.
		if e != nil {
			return e
		}
		offset += int64(len(line))
		var row map[string]any
		switch kind {
		case "events":
			var event model.SecurityEvent
			if json.Unmarshal(line, &event) == nil && event.EventID != "" {
				ns, pod := "", ""
				if event.Kubernetes != nil {
					ns = event.Kubernetes.Namespace
					pod = event.Kubernetes.Pod
				}
				file, ip := "", ""
				if event.File != nil {
					file = event.File.Path
				}
				if event.Network != nil {
					ip = event.Network.DestinationIP
				}
				sensorID, cluster := "", ""
				if event.Sensor != nil {
					sensorID, cluster = event.Sensor.ID, event.Sensor.Cluster
				}
				row = map[string]any{"sensor_id": sensorID, "cluster": cluster, "received_at": event.ReceivedAt, "event_id": event.EventID, "timestamp": event.Timestamp, "event_type": event.EventType, "namespace": ns, "pod": pod, "process_binary": event.Process.Binary, "file_path": file, "destination_ip": ip, "payload": strings.TrimSuffix(string(line), "\n")}
			}
		case "alerts":
			var alert model.SecurityAlert
			if json.Unmarshal(line, &alert) == nil && alert.AlertID != "" {
				ns, pod := "", ""
				if alert.Kubernetes != nil {
					ns = alert.Kubernetes.Namespace
					pod = alert.Kubernetes.Pod
				}
				sensorIDs := alert.SensorIDs
				if sensorIDs == nil {
					sensorIDs = []string{}
				}
				row = map[string]any{"sensor_ids": sensorIDs, "cluster": alert.Cluster, "alert_id": alert.AlertID, "timestamp": alert.Timestamp, "rule_id": alert.RuleID, "severity": alert.Severity, "namespace": ns, "pod": pod, "payload": strings.TrimSuffix(string(line), "\n")}
			}
		default:
			return fmt.Errorf("unknown stream %s", kind)
		}
		if row != nil {
			batch = append(batch, row)
		} else {
			log.Printf("ingest: skipping malformed %s JSONL record in %s near byte %d", kind, path, offset)
		}
	}
	if offset != cur.Offset {
		if err = db.Insert(ctx, kind, batch); err != nil {
			return err
		}
		cp.Files[path] = fileCursor{Identity: ident, Offset: offset}
		if err = saveCheckpoint(checkpoint, cp); err != nil {
			return err
		}
	}
	if immutable && offset == cur.Offset {
		// Cursor transferred from the former active path after a rename.
		cp.Files[path] = cur
		if err := saveCheckpoint(checkpoint, cp); err != nil {
			return err
		}
	}
	// Archive is immutable. Delete only when committed offset reached the full segment.
	if immutable && cp.Files[path].Offset >= st.Size() && st.Size() > 0 {
		if err = os.Remove(path); err != nil {
			return err
		}
		delete(cp.Files, path)
		// Keep the original path identity checkpoint as a migration aid for renamed active files.
		if err = saveCheckpoint(checkpoint, cp); err != nil {
			return err
		}
	}
	return nil
}
