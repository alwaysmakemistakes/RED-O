package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWebChildSignatureDoesNotMatchOtherProcess(t *testing.T) {
	if isWebChild(os.Getpid()) || isWebChild(0) || isWebChild(-1) {
		t.Fatal("unmanaged or invalid PID must not match Web child")
	}
}

func TestWebPIDDoesNotStopOtherProcess(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := os.Mkdir("data", 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWebPIDAtomic(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	pid, err := readWebPID()
	if err != nil || pid != os.Getpid() {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
	if statusWeb() != 1 {
		t.Fatal("unmanaged PID must not be reported as Web")
	}
	if err := stopWeb(); err == nil {
		t.Fatal("stale PID must not stop another process")
	}
	if _, err := os.Stat(filepath.Join("data", "web.lock")); err != nil {
		t.Fatal("expected independent Web lock", err)
	}
}
