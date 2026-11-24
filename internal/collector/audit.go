package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// FollowAuditFile follows a Kubernetes audit JSONL file in read-only mode.
// It begins at EOF by default to avoid replaying old audit actions on each
// restart. It does not provide durable audit delivery or a cursor across restarts.
// Configure rotation/retention at the API server. A partial trailing record is
// held until completed. On inode replacement the new file is read from start.
func FollowAuditFile(ctx context.Context, path string, fromStart bool, handle func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Kubernetes audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	var offset int64
	if !fromStart {
		offset, err = f.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat Kubernetes audit log: %w", err)
		}
		openInfo, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(info, openInfo) {
			next, e := os.Open(path)
			if e != nil {
				return e
			}
			f.Close()
			f = next
			offset = 0
		} else if info.Size() < offset {
			offset = 0
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		r := bufio.NewReader(f)
		for {
			line, e := r.ReadBytes('\n')
			if e == nil {
				if err := handle(line); err != nil {
					return err
				}
				offset += int64(len(line))
				continue
			}
			if e != io.EOF {
				return e
			}
			// Do not advance past an unterminated JSON object.
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
