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

const ingesterChildCommand = "__ingester-run"

// A PID is trusted only if its command line identifies this daemon child.
// A stale PID file must never allow stopping an unrelated reused PID.
func isIngesterChild(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	fields := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	if len(fields) < 2 || string(fields[1]) != ingesterChildCommand {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	idx := bytes.LastIndex(stat, []byte(") "))
	return idx >= 0 && len(stat) > idx+2 && stat[idx+2] != 'Z'
}

func ingesterPIDFile() string { return filepath.Join("data", "ingester.pid") }
func ingesterLogFile() string { return filepath.Join("data", "ingester.log") }

func readIngesterPID() (int, error) {
	b, err := os.ReadFile(ingesterPIDFile())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid Ingester PID file")
	}
	return pid, nil
}

func ingesterLock() (*os.File, error) {
	f, err := os.OpenFile("data/ingester.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlockIngester(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }

func startIngesterInBackground(args []string) error {
	lock, err := ingesterLock()
	if err != nil {
		return err
	}
	defer unlockIngester(lock)
	if pid, e := readIngesterPID(); e == nil && isIngesterChild(pid) {
		return fmt.Errorf("Ingester already running (PID %d); use 'red-o ingester status'", pid)
	}
	logfile, err := os.OpenFile(ingesterLogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logfile.Close()
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(binary, append([]string{ingesterChildCommand}, args...)...)
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
	if err := writeIngesterPIDAtomic(pid); err != nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		return err
	}
	time.Sleep(350 * time.Millisecond)
	if !isIngesterChild(pid) {
		_ = os.Remove(ingesterPIDFile())
		return fmt.Errorf("Ingester exited during startup; inspect %s", ingesterLogFile())
	}
	fmt.Printf("RED-O Ingester started in background (PID %d)\nLog: %s\nStop: red-o ingester stop\n", pid, ingesterLogFile())
	return nil
}

func writeIngesterPIDAtomic(pid int) error {
	f, err := os.CreateTemp("data", ".ingester.pid-*")
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
	return os.Rename(f.Name(), ingesterPIDFile())
}

func statusIngester() int {
	pid, err := readIngesterPID()
	if err != nil || !isIngesterChild(pid) {
		fmt.Println("RED-O Ingester is not running")
		return 1
	}
	fmt.Printf("RED-O Ingester running (PID %d); log: %s\n", pid, ingesterLogFile())
	return 0
}

func stopIngester() error {
	lock, err := ingesterLock()
	if err != nil {
		return err
	}
	defer unlockIngester(lock)
	pid, err := readIngesterPID()
	if err != nil || !isIngesterChild(pid) {
		return errors.New("RED-O Ingester is not running (no matching managed process)")
	}
	if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if !isIngesterChild(pid) {
			_ = os.Remove(ingesterPIDFile())
			fmt.Printf("RED-O Ingester stopped (PID %d)\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("Ingester PID %d did not stop in 10s; check %s", pid, ingesterLogFile())
}

func tailIngesterLog() error {
	f, err := os.Open(ingesterLogFile())
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}
