package collector

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFollowAuditFilePartialAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	os.WriteFile(path, []byte("old\n"), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	got := []string{}
	done := make(chan error, 1)
	go func() {
		done <- FollowAuditFile(ctx, path, false, func(b []byte) error { mu.Lock(); got = append(got, string(b)); mu.Unlock(); return nil })
	}()
	time.Sleep(100 * time.Millisecond)
	appendBytes := func(s string) {
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.WriteString(s)
		f.Close()
	}
	appendBytes("one")
	time.Sleep(350 * time.Millisecond)
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("partial record imported: %+v", got)
	}
	appendBytes("\n")
	time.Sleep(350 * time.Millisecond)
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("two\n"), 0600)
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != "one\n" || got[1] != "two\n" {
		t.Fatalf("got %#v", got)
	}
}
