package multisensor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"runtime-detector/internal/collector"
)

type message struct {
	record   *Record
	finished string
	err      error
}

// Run runs all configured inputs concurrently. Each has its own reconnection or
// follower logic. A bounded channel applies backpressure; it never silently
// discards messages. All callback invocations are serialized in the caller.
// onEnd is called once per source after the source has stopped.
func Run(ctx context.Context, c Config, onRecord func(Record) error, onTick func(time.Time) error, onEnd func(string) error) error {
	if err := c.Validate(); err != nil {
		return err
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	messages := make(chan message, 1024)
	var wg sync.WaitGroup
	for _, sensor := range c.Sensors {
		s := sensor
		wg.Add(1)
		go func() {
			defer wg.Done()
			report := func(line []byte) error {
				rec := Record{Sensor: s, Data: append([]byte(nil), line...), ReceivedAt: time.Now().UTC()}
				select {
				case messages <- message{record: &rec}:
					return nil
				case <-workCtx.Done():
					return workCtx.Err()
				}
			}
			err := stream(workCtx, s, report)
			if errors.Is(err, context.Canceled) {
				err = nil
			}
			// Exit notification must reach the coordinator on normal EOF and failures.
			select {
			case messages <- message{finished: s.ID, err: err}:
			case <-workCtx.Done():
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	remaining := len(c.Sensors)
	var firstErr error
	for remaining > 0 {
		select {
		case m := <-messages:
			if m.record != nil {
				if firstErr == nil {
					if err := onRecord(*m.record); err != nil {
						firstErr = err
						cancel()
					}
				}
			} else if m.finished != "" {
				remaining--
				if firstErr == nil {
					if err := onEnd(m.finished); err != nil {
						firstErr = err
						cancel()
					}
				}
				if m.err != nil && firstErr == nil {
					firstErr = fmt.Errorf("sensor %s: %w", m.finished, m.err)
					cancel()
				}
			}
		case now := <-ticker.C:
			if firstErr == nil {
				if err := onTick(now); err != nil {
					firstErr = err
					cancel()
				}
			}
		case <-ctx.Done():
			cancel()
			// A canceled source can terminate without sending finished. Wait for
			// workers, then drain already-received records for best-effort
			// persistence during graceful termination.
			<-done
			for len(messages) > 0 {
				m := <-messages
				if m.record != nil {
					if firstErr == nil {
						if e := onRecord(*m.record); e != nil {
							firstErr = e
						}
					}
				} else if m.finished != "" {
					if firstErr == nil {
						if e := onEnd(m.finished); e != nil {
							firstErr = e
						}
					}
				}
			}
			return firstErr
		case <-done:
			// All streams exited. Drain notifications/records from buffered channel.
			for len(messages) > 0 {
				m := <-messages
				if m.record != nil {
					if firstErr == nil {
						if err := onRecord(*m.record); err != nil {
							firstErr = err
						}
					}
				} else if m.finished != "" {
					remaining--
					if firstErr == nil {
						if err := onEnd(m.finished); err != nil {
							firstErr = err
						}
					}
					if m.err != nil && firstErr == nil {
						firstErr = fmt.Errorf("sensor %s: %w", m.finished, m.err)
					}
				}
			}
			return firstErr
		}
	}
	return firstErr
}

func stream(ctx context.Context, s Sensor, deliver func([]byte) error) error {
	switch s.Type {
	case "tetra":
		binary := s.Kubectl
		if binary == "" {
			binary = "kubectl"
		}
		container := s.Container
		if container == "" {
			container = "tetragon"
		}
		return collector.StreamTetra(ctx, collector.TetraConfig{
			Kubectl: binary, Context: s.Context, Namespace: s.Namespace, Pod: s.Pod, Container: container,
			FilterNamespace: s.EventNamespace, MinBackoff: time.Second, MaxBackoff: 30 * time.Second,
			OnConnect:    func() { fmt.Fprintf(os.Stderr, "sensor %s connected (pod=%s)\n", s.ID, s.Pod) },
			OnDisconnect: func(err error) { fmt.Fprintf(os.Stderr, "sensor %s disconnected: %v\n", s.ID, err) },
		}, deliver)
	case "audit":
		return collector.FollowAuditFile(ctx, s.Path, s.FromStart, deliver)
	case "jsonl":
		f, err := os.Open(s.Path)
		if err != nil {
			return err
		}
		defer f.Close()
		return collector.ReadJSONL(ctx, f, deliver)
	default:
		return fmt.Errorf("invalid sensor type: %s", s.Type)
	}
}
