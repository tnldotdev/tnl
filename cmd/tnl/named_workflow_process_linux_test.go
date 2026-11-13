package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type namedWorkflowLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *namedWorkflowLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(data)
}

func (l *namedWorkflowLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

// the fixture owns each foreground CLI and explicitly started local owner.
// done closes only after Wait joins the process and its output writers.
type namedWorkflowProcess struct {
	done chan struct{}
	err  error
	log  namedWorkflowLog
	stop func()
}

func startNamedWorkflowCommand(t *testing.T, command *exec.Cmd) *namedWorkflowProcess {
	t.Helper()
	p := &namedWorkflowProcess{done: make(chan struct{})}
	command.Stdout, command.Stderr = &p.log, &p.log
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = command.Wait()
		close(p.done)
	}()
	p.stop = sync.OnceFunc(func() {
		select {
		case <-p.done:
		default:
			_ = command.Process.Signal(os.Interrupt)
		}
		select {
		case <-p.done:
			if p.err != nil {
				t.Errorf("named workflow process failed: %v\n%s", p.err, p.log.String())
			}
		case <-time.After(15 * time.Second):
			_ = command.Process.Kill()
			<-p.done
			t.Errorf("named workflow process did not join shutdown\n%s", p.log.String())
		}
	})
	t.Cleanup(p.stop)
	return p
}

func (p *namedWorkflowProcess) wait(t *testing.T, timeout time.Duration, check func(context.Context) (bool, string)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			t.Fatalf("named workflow process exited before ready: %v\n%s", p.err, p.log.String())
		default:
		}
		ready, detail := check(ctx)
		if ready {
			return
		}
		select {
		case <-p.done:
			t.Fatalf("named workflow process exited before ready: %v\nlast observation: %s\n%s", p.err, detail, p.log.String())
		case <-ctx.Done():
			t.Fatalf("named workflow process did not become ready: %v\nlast observation: %s\n%s", ctx.Err(), detail, p.log.String())
		case <-ticker.C:
		}
	}
}
