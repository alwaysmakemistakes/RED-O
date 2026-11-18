package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Writer rotates complete JSONL records, never splits records across segments.
// An error is returned when the segment quota is exhausted: data is not silently discarded.
type Writer struct {
	mu               sync.Mutex
	path             string
	f                *os.File
	maxBytes         int64
	maxSegments      int
	size             int64
	counter          uint64
	rawRetention     time.Duration
	rawMaxTotalBytes int64
}

func Open(path string, maxBytes int64, maxSegments int) (*Writer, error) {
	if maxBytes < 0 || maxSegments < 1 {
		return nil, errors.New("invalid rotation limits")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{path: path, f: f, maxBytes: maxBytes, maxSegments: maxSegments, size: st.Size()}, nil
}

func Segments(path string) ([]string, error) {
	list, err := filepath.Glob(path + ".segment-*")
	if err != nil {
		return nil, err
	}
	sort.Strings(list)
	return list, nil
}

func (w *Writer) rotate() error {
	if w.rawMaxTotalBytes > 0 {
		if err := w.pruneRawLocked(true); err != nil {
			return err
		}
	}
	segments, err := Segments(w.path)
	if err != nil {
		return err
	}
	if len(segments) >= w.maxSegments {
		return fmt.Errorf("JSONL segment quota exhausted for %s (%d segments); run Web ingest or increase -storage-max-segments", w.path, w.maxSegments)
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	w.counter++
	rotated := fmt.Sprintf("%s.segment-%019d-%06d", w.path, time.Now().UTC().UnixNano(), w.counter)
	if err := os.Rename(w.path, rotated); err != nil {
		return err
	}
	// A failure here is safe for persisted records; reopening must be attempted on restart.
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	w.f = f
	w.size = 0
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.maxBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
