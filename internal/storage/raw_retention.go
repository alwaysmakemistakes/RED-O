package storage

import (
	"fmt"
	"log"
	"os"
	"sort"
	"time"
)

// OpenRaw uses a separate, explicitly lossy retention policy for raw Tetragon
// telemetry. Unlike events and alerts, closed raw segments are not imported by
// the independent Ingester and must be bounded independently.
func OpenRaw(path string, segmentBytes int64, maxSegments int, retention time.Duration, maxTotalBytes int64) (*Writer, error) {
	if retention < 0 || maxTotalBytes <= 0 || maxSegments < 1 {
		return nil, fmt.Errorf("invalid raw retention: duration >= 0, max bytes > 0 and max segments >= 1 required")
	}
	if segmentBytes > 0 && segmentBytes > maxTotalBytes {
		return nil, fmt.Errorf("raw segment size (%d) exceeds total raw storage budget (%d)", segmentBytes, maxTotalBytes)
	}
	w, err := Open(path, segmentBytes, maxSegments)
	if err != nil {
		return nil, err
	}
	w.rawRetention = retention
	w.rawMaxTotalBytes = maxTotalBytes
	w.mu.Lock()
	err = w.pruneRawLocked(false)
	w.mu.Unlock()
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

type rawSegment struct {
	path     string
	size     int64
	modified time.Time
}

// pruneRawLocked is only called with w.mu held. The active file is NEVER
// deleted. Oldest immutable segments go first. If the active file alone exceeds
// the budget, report an error instead of deleting unrelated data.
func (w *Writer) pruneRawLocked(needRotation bool) error {
	paths, err := Segments(w.path)
	if err != nil {
		return err
	}
	segments := make([]rawSegment, 0, len(paths))
	var used int64 = w.size
	for _, path := range paths {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("refusing to prune non-regular raw segment %s", path)
		}
		used += st.Size()
		segments = append(segments, rawSegment{path: path, size: st.Size(), modified: st.ModTime()})
	}
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].modified.Equal(segments[j].modified) {
			return segments[i].path < segments[j].path
		}
		return segments[i].modified.Before(segments[j].modified)
	})
	now := time.Now()
	for len(segments) > 0 {
		oldest := segments[0]
		expired := w.rawRetention > 0 && now.Sub(oldest.modified) > w.rawRetention
		limit := len(segments) > w.maxSegments || (needRotation && len(segments) >= w.maxSegments)
		overBudget := used > w.rawMaxTotalBytes
		if !expired && !limit && !overBudget {
			break
		}
		if err := os.Remove(oldest.path); err != nil {
			return fmt.Errorf("remove raw segment %s: %w", oldest.path, err)
		}
		log.Printf("raw retention: removed closed segment %s (expired=%t quota=%t budget=%t)", oldest.path, expired, limit, overBudget)
		used -= oldest.size
		segments = segments[1:]
	}
	if used > w.rawMaxTotalBytes {
		return fmt.Errorf("active raw file %s exceeds max raw budget %d bytes", w.path, w.rawMaxTotalBytes)
	}
	return nil
}
