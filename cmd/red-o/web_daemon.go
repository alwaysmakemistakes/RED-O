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

const webChildCommand = "__web-run"

// A PID is trusted only if its command line identifies this daemon child.
// A stale PID file must never allow stopping an unrelated reused PID.
func isWebChild(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	fields := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	if len(fields) < 2 || string(fields[1]) != webChildCommand {
		return false
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	idx := bytes.LastIndex(stat, []byte(") "))
	return idx >= 0 && len(stat) > idx+2 && stat[idx+2] != 'Z'
}

func webPIDFile() string { return filepath.Join("data", "web.pid") }
func webLogFile() string { return filepath.Join("data", "web.log") }

func readWebPID() (int, error) {
	b, err := os.ReadFile(webPIDFile())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("invalid Web PID file")
	}
	return pid, nil
}

func webLock() (*os.File, error) {
	f, err := os.OpenFile("data/web.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlockWeb(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }

func startWebInBackground(args []string) error {
	lock, err := webLock()
	if err != nil {
		return err
	}
	defer unlockWeb(lock)
	if pid, e := readWebPID(); e == nil && isWebChild(pid) {
		return fmt.Errorf("Web already running (PID %d); use 'red-o web status'", pid)
	}
	logfile, err := os.OpenFile(webLogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logfile.Close()
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(binary, append([]string{webChildCommand}, args...)...)
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
	if err := writeWebPIDAtomic(pid); err != nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		return err
	}
	time.Sleep(350 * time.Millisecond)
	if !isWebChild(pid) {
		_ = os.Remove(webPIDFile())
		return fmt.Errorf("Web exited during startup; inspect %s", webLogFile())
	}
	fmt.Printf("RED-O Web started in background (PID %d)\nLog: %s\nStop: red-o web stop\n", pid, webLogFile())
	return nil
}

func writeWebPIDAtomic(pid int) error {
	f, err := os.CreateTemp("data", ".web.pid-*")
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
	return os.Rename(f.Name(), webPIDFile())
}

func statusWeb() int {
	pid, err := readWebPID()
	if err != nil || !isWebChild(pid) {
		fmt.Println("RED-O Web is not running")
		return 1
	}
	fmt.Printf("RED-O Web running (PID %d); log: %s\n", pid, webLogFile())
	return 0
}

func stopWeb() error {
	lock, err := webLock()
	if err != nil {
		return err
	}
	defer unlockWeb(lock)
	pid, err := readWebPID()
	if err != nil || !isWebChild(pid) {
		return errors.New("RED-O Web is not running (no matching managed process)")
	}
	if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if !isWebChild(pid) {
			_ = os.Remove(webPIDFile())
			fmt.Printf("RED-O Web stopped (PID %d)\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("Web PID %d did not stop in 10s; check %s", pid, webLogFile())
}

func tailWebLog() error {
	f, err := os.Open(webLogFile())
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}
