package tnldruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// commandOwner is the only caller of Wait. exec owns both output pumps.
// WaitDelay keeps their join from hanging if a child retains an output FD.
// repeated shutdown is safe: interrupt, wait, kill, then wait again.
type commandOwner struct {
	command *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	err     error
	stop    sync.Once
	stopErr error
}

func startOwnedCommand(command *exec.Cmd, finish func()) (*commandOwner, error) {
	command.WaitDelay = time.Second
	p := &commandOwner{command: command, done: make(chan struct{})}
	if err := command.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := command.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		if finish != nil {
			finish()
		}
		close(p.done)
	}()
	return p, nil
}

func (p *commandOwner) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func waitForDone(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func waitForDoneWithin(done <-chan struct{}, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return waitForDone(ctx, done)
}

func (p *commandOwner) shutdown(grace, reap time.Duration) error {
	p.stop.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		if err := p.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			p.stopErr = fmt.Errorf("interrupt: %w", err)
		}
		if waitForDoneWithin(p.done, grace) == nil {
			return
		}
		p.stopErr = errors.Join(p.stopErr, errors.New("process exceeded interrupt grace period; killed"))
		if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			p.stopErr = errors.Join(p.stopErr, fmt.Errorf("kill: %w", err))
		}
		if err := waitForDoneWithin(p.done, reap); err != nil {
			p.stopErr = errors.Join(p.stopErr, fmt.Errorf("reap/output join: %w", err))
		}
	})
	return p.stopErr
}
