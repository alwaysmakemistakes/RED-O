package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIngesterChildSignatureDoesNotMatchOtherProcess(t *testing.T) {
	if isIngesterChild(os.Getpid()) || isIngesterChild(0) || isIngesterChild(-1) {
		t.Fatal("unmanaged or invalid PID must not match Ingester child")
	}
}

func TestIngesterPIDDoesNotStopOtherProcess(t *testing.T) {
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
	if err := writeIngesterPIDAtomic(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	pid, err := readIngesterPID()
	if err != nil || pid != os.Getpid() {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
	if statusIngester() != 1 {
		t.Fatal("unmanaged PID must not be reported as Ingester")
	}
	if err := stopIngester(); err == nil {
		t.Fatal("stale PID must not stop another process")
	}
	if _, err := os.Stat(filepath.Join("data", "ingester.lock")); err != nil {
		t.Fatal("expected independent Ingester lock", err)
	}
}
