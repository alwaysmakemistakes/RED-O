package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDetectorChildSignatureDoesNotMatchOtherProcess(t *testing.T) {
	if isDetectorChild(os.Getpid()) {
		t.Fatal("unit-test process must not be identified as the detector daemon")
	}
	if isDetectorChild(-1) || isDetectorChild(0) {
		t.Fatal("nonpositive PIDs must not be accepted")
	}
}

func TestPIDFileAndStalePIDHandling(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := os.Mkdir("data", 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePIDAtomic(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	pid, err := readDetectorPID()
	if err != nil || pid != os.Getpid() {
		t.Fatalf("pid = %d, err = %v", pid, err)
	}
	if got := statusDetector(); got != 1 {
		t.Fatalf("status = %d; expected unmanaged PID to be ignored", got)
	}
	if err := stopDetector(); err == nil {
		t.Fatal("must not stop an unrelated PID")
	}
	if err := os.WriteFile(filepath.Join("data", "detector.pid"), []byte(strconv.Itoa(-5)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDetectorPID(); err == nil {
		t.Fatal("negative PID accepted")
	}
}
