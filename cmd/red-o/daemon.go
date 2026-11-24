package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const detectorChildCommand = "__detector-run"

func detectorDefaults() []string {
	return []string{"-source", "tetra", "-mode", "soc", "-rules", "configs/rules.json", "-correlations", "configs/correlations.json", "-events", "data/live-events.jsonl", "-alerts", "data/live-alerts.jsonl", "-exceptions", "data/exceptions.json", "-heartbeat", "data/collector-heartbeat.json", "-gap-log", "data/collector-gaps.jsonl", "-metrics-listen", "127.0.0.1:9095"}
}

// A PID is trusted only if its command line identifies this daemon child.
// A stale PID file must never allow stopping an unrelated reused PID.
func isDetectorChild(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	fields := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	if len(fields) < 2 || string(fields[1]) != detectorChildCommand {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	idx := bytes.LastIndex(stat, []byte(") "))
	return idx >= 0 && len(stat) > idx+2 && stat[idx+2] != 'Z'
}

func pidFile() string { return filepath.Join("data", "detector.pid") }
func logFile() string { return filepath.Join("data", "detector.log") }

func readDetectorPID() (int, error) {
	b, err := os.ReadFile(pidFile())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid detector PID file")
	}
	return pid, nil
}

func detectorLock() (*os.File, error) {
	f, err := os.OpenFile("data/detector.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlockDetector(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }

func startDetectorInBackground(args []string) error {
	lock, err := detectorLock()
	if err != nil {
		return err
	}
	defer unlockDetector(lock)
	if pid, e := readDetectorPID(); e == nil && isDetectorChild(pid) {
		return fmt.Errorf("detector already running (PID %d); use 'red-o detector status'", pid)
	}
	logfile, err := os.OpenFile(logFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logfile.Close()
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(binary, append([]string{detectorChildCommand}, args...)...)
	command.Dir, _ = os.Getwd()
	command.Stdin, err = os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer command.Stdin.(*os.File).Close()
	command.Stdout = logfile
	command.Stderr = logfile
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	pid := command.Process.Pid
	// Release the child process handle; the daemon's lifetime is independent
	// of the initiating terminal and its shell job table.
	_ = command.Process.Release()
	if err := writePIDAtomic(pid); err != nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		return err
	}
	time.Sleep(350 * time.Millisecond)
	if !isDetectorChild(pid) {
		_ = os.Remove(pidFile())
		return fmt.Errorf("detector exited during startup; inspect %s", logFile())
	}
	fmt.Printf("RED-O detector started in background (PID %d)\nLog: %s\nStop: red-o detector stop\n", pid, logFile())
	return nil
}

func writePIDAtomic(pid int) error {
	f, err := os.CreateTemp("data", ".detector.pid-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = fmt.Fprintf(f, "%d\n", pid); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), pidFile())
}

func statusDetector() int {
	pid, err := readDetectorPID()
	if err != nil || !isDetectorChild(pid) {
		fmt.Println("RED-O detector is not running")
		return 1
	}
	fmt.Printf("RED-O detector running (PID %d); log: %s\n", pid, logFile())
	return 0
}

func stopDetector() error {
	lock, err := detectorLock()
	if err != nil {
		return err
	}
	defer unlockDetector(lock)
	pid, err := readDetectorPID()
	if err != nil || !isDetectorChild(pid) {
		return errors.New("RED-O detector is not running (no matching managed process)")
	}
	if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if !isDetectorChild(pid) {
			_ = os.Remove(pidFile())
			fmt.Printf("RED-O detector stopped (PID %d)\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("detector PID %d did not stop in 10s; check %s", pid, logFile())
}

func tailDetectorLog() error {
	f, err := os.Open(logFile())
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}
