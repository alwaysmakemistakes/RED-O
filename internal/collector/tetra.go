package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TetraConfig connects to the local Tetragon Unix gRPC socket via the official
// tetra client running in the Tetragon pod. Kubernetes exec is the transport.
// It is live-only: a reconnect does not replay events missed during downtime.
type TetraConfig struct {
	Kubectl         string
	Namespace       string
	Context         string // optional kubeconfig context
	Pod             string // explicit Tetragon pod; required in multi-sensor mode
	DaemonSet       string
	Container       string
	FilterNamespace string
	MinBackoff      time.Duration
	MaxBackoff      time.Duration
	OnConnect       func()
	OnDisconnect    func(error)
}

func (c TetraConfig) validate() error {
	if c.Kubectl == "" || c.Namespace == "" || (c.DaemonSet == "" && c.Pod == "") || c.Container == "" {
		return errors.New("tetra kubectl, namespace, daemonset and container required")
	}
	for _, v := range []string{c.Namespace, c.DaemonSet, c.Container} {
		if strings.HasPrefix(v, "-") {
			return fmt.Errorf("invalid kubernetes selector %q", v)
		}
	}
	if c.MinBackoff <= 0 || c.MaxBackoff < c.MinBackoff {
		return errors.New("invalid reconnect backoff")
	}
	return nil
}

// StreamTetra stays connected until ctx cancellation or a processing failure.
// A child process is re-created after EOF or a kubectl/tetra failure.
func StreamTetra(ctx context.Context, c TetraConfig, handle func([]byte) error) error {
	if err := c.validate(); err != nil {
		return err
	}
	delay := c.MinBackoff
	for ctx.Err() == nil {
		target := "ds/" + c.DaemonSet
		if c.Pod != "" {
			target = "pod/" + c.Pod
		}
		args := []string{}
		if c.Context != "" {
			args = append(args, "--context", c.Context)
		}
		args = append(args, "-n", c.Namespace, "exec", target, "-c", c.Container, "--", "tetra", "getevents", "-o", "json")
		if c.FilterNamespace != "" {
			args = append(args, "--namespace", c.FilterNamespace)
		}
		if filepath.Base(c.Kubectl) == "k3s" {
			args = append([]string{"kubectl"}, args...)
		}
		cmd := exec.CommandContext(ctx, c.Kubectl, args...)
		// If a kubectl wrapper leaves descendants holding stdout open, shutdown
		// must not block indefinitely waiting for pipe EOF.
		cmd.WaitDelay = 2 * time.Second
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("pipe tetra: %w", err)
		}
		cmd.Stderr = os.Stderr
		started := time.Now()
		if err = cmd.Start(); err == nil {
			if c.OnConnect != nil {
				c.OnConnect()
			}
			readDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = stdout.Close() // unblock a decoder waiting on idle kubectl stdout
				case <-readDone:
				}
			}()
			err = readJSONStream(ctx, stdout, handle)
			close(readDone)
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				// Stop the child on handler errors rather than allowing it to block on stdout.
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return fmt.Errorf("tetra stream processing: %w", err)
			}
			waitErr := cmd.Wait()
			if err == nil {
				err = waitErr
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		// A connection that survived a normal operational interval is not
		// part of the previous failure streak. Reset exponential backoff.
		if time.Since(started) >= 30*time.Second {
			delay = c.MinBackoff
		}
		if c.OnDisconnect != nil {
			if err == nil {
				err = io.EOF
			}
			c.OnDisconnect(err)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			return nil
		case <-t.C:
		}
		if delay < c.MaxBackoff/2 {
			delay *= 2
		} else {
			delay = c.MaxBackoff
		}
	}
	return nil
}

// readJSONStream accepts both compact JSONL and pretty-printed JSON objects.
func readJSONStream(ctx context.Context, r io.Reader, handle func([]byte) error) error {
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var raw json.RawMessage
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode tetra JSON stream: %w", err)
		}
		if len(raw) > MaxEventBytes {
			return fmt.Errorf("tetra event exceeds %d bytes", MaxEventBytes)
		}
		if err := handle(raw); err != nil {
			return err
		}
	}
}
