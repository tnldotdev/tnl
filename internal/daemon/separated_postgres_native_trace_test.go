package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/runtimetrace"
)

// this parent owns only fixture IPC. the child owns runtime/trace and artifacts;
// no command changes visitor transport, authentication, or connector lifetime.
type postgresNativeTrace struct {
	component                   string
	ctx                         context.Context
	cancel                      context.CancelFunc
	commands, replies           *os.File
	childCommands, childReplies *os.File
	done                        chan struct{}
	mailboxes                   [runtimetrace.MaxCommands]chan runtimetrace.Reply
	sendMu                      sync.Mutex
	next, triggerID             int
	mu                          sync.Mutex
	err                         error
	receipt                     *runtimetrace.Receipt
	afterStart, close, finish   sync.Once
	finishErr                   error
}

// prepare before startOwnedCommand. AfterStart must run immediately after Start
// succeeds; Close also handles startup failure and is registered as a fallback.
func prepareNativeTrace(t *testing.T, ctx context.Context, command *exec.Cmd, component string) (*postgresNativeTrace, error) {
	t.Helper()
	directory := filepath.Join("/results", "native-late-connect-postgres-warm-"+component)
	d, err := newPostgresNativeTrace(ctx, command, component, directory)
	if d != nil {
		t.Cleanup(d.Close)
	}
	return d, err
}

func newPostgresNativeTrace(ctx context.Context, command *exec.Cmd, component, directory string) (*postgresNativeTrace, error) {
	if command == nil || len(command.ExtraFiles) != 0 || command.Process != nil || !runtimetrace.SimpleName(component) || !filepath.IsAbs(directory) {
		return nil, errors.New("native trace needs an unstarted command without ExtraFiles and a simple component")
	}
	childCommands, commands, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	replies, childReplies, err := os.Pipe()
	if err != nil {
		_ = childCommands.Close()
		_ = commands.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	d := &postgresNativeTrace{ctx: ctx, cancel: cancel, component: component, commands: commands, replies: replies, childCommands: childCommands, childReplies: childReplies, done: make(chan struct{})}
	for i := range d.mailboxes {
		d.mailboxes[i] = make(chan runtimetrace.Reply, 1)
	}
	command.ExtraFiles = []*os.File{childCommands, childReplies}
	command.Args = append(command.Args, runtimetrace.CommandFDFlag+"=3", runtimetrace.ReplyFDFlag+"=4", runtimetrace.DirectoryFlag+"="+directory)
	go d.pump()
	return d, nil
}

func (d *postgresNativeTrace) AfterStart() {
	if d == nil {
		return
	}
	d.afterStart.Do(func() { _ = d.childCommands.Close(); _ = d.childReplies.Close() })
}

func (d *postgresNativeTrace) pump() {
	defer close(d.done)
	stop := context.AfterFunc(d.ctx, func() { _ = d.commands.Close(); _ = d.replies.Close() })
	defer stop()
	decoder := runtimetrace.NewDecoder(d.replies)
	for n := 1; n <= runtimetrace.MaxCommands; n++ {
		var r runtimetrace.Reply
		if err := decoder.Read(&r); err != nil {
			if !errors.Is(err, io.EOF) || n == 1 {
				d.recordError(errors.New("native trace reply pipe ended before acknowledgement"))
			}
			return
		}
		if r.ID != n || (r.Kind != runtimetrace.Arm && r.Kind != runtimetrace.Trigger && r.Kind != runtimetrace.Export) {
			d.recordError(errors.New("native trace reply ID/kind invalid"))
			return
		}
		d.mu.Lock()
		d.receipt = r.Receipt
		d.mu.Unlock()
		d.mailboxes[r.ID-1] <- r
		if r.Kind == runtimetrace.Export {
			return
		}
	}
	d.recordError(errors.New("native trace reply limit exceeded"))
}

func (d *postgresNativeTrace) recordError(err error) {
	d.mu.Lock()
	d.err = errors.Join(d.err, err)
	d.mu.Unlock()
}

func (d *postgresNativeTrace) send(ctx context.Context, c runtimetrace.Command) (int, error) {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := d.ctx.Err(); err != nil {
		return 0, err
	}
	c.ID = d.next + 1
	if err := c.Validate(); err != nil {
		return 0, err
	}
	// at most four small commands, with no request data, fit in the pipe even
	// while the child holds its tail. cancellation closes a blocked write.
	stop := context.AfterFunc(ctx, func() { _ = d.commands.Close() })
	err := runtimetrace.WriteFrame(d.commands, c)
	stopped := stop()
	if err == nil && !stopped {
		err = ctx.Err()
	}
	if err != nil {
		d.recordError(err)
		return 0, err
	}
	d.next = c.ID
	return c.ID, nil
}

func (d *postgresNativeTrace) wait(ctx context.Context, id int, kind runtimetrace.Kind) error {
	if id < 1 || id > len(d.mailboxes) {
		return errors.New("invalid native trace acknowledgement ID")
	}
	accept := func(r runtimetrace.Reply) error {
		if r.Kind != kind {
			return errors.New("unexpected native trace acknowledgement kind")
		}
		if r.Error != "" {
			return fmt.Errorf("native trace: %s", r.Error)
		}
		return nil
	}
	// a completed pump can still have the final ACK waiting in its mailbox.
	select {
	case r := <-d.mailboxes[id-1]:
		return accept(r)
	default:
	}
	select {
	case r := <-d.mailboxes[id-1]:
		return accept(r)
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		select {
		case r := <-d.mailboxes[id-1]:
			return accept(r)
		default:
			return errors.New("native trace reply pump ended before requested acknowledgement")
		}
	}
}

// Arm must return successfully before phase.Start. it is not an asynchronous
// notification and does not share the visitor runtime's recorder.
func (d *postgresNativeTrace) Arm(ctx context.Context, phase connectLoadPhase) error {
	if d == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	id, err := d.send(ctx, runtimetrace.Command{Kind: runtimetrace.Arm, Phase: phase.Name, Component: d.component, Start: phase.Start, Duration: phase.Duration})
	if err == nil {
		err = d.wait(ctx, id, runtimetrace.Arm)
	}
	if err == nil && !time.Now().Before(phase.Start) {
		err = errors.New("native trace arm acknowledgement arrived at or after phase start")
	}
	d.recordError(err)
	return err
}

// Trigger is safe for the visitor's 2s Notify callback: it sends only, never
// waits for the one-second child tail, WriteTo, Stop, or an acknowledgement.
func (d *postgresNativeTrace) Trigger(ctx context.Context, e postgresLateTrigger) error {
	if d == nil {
		return nil
	}
	event := &runtimetrace.Event{Slot: e.Slot, Kind: e.Kind, Started: e.Started, Completed: e.Completed, Observed: e.Observed, TriggerLag: e.TriggerLag, MarkerStarted: e.MarkerStarted, MarkerCompleted: e.MarkerCompleted, MarkerEmitted: e.MarkerEmitted}
	id, err := d.send(ctx, runtimetrace.Command{Kind: runtimetrace.Trigger, Event: event})
	if err == nil {
		d.sendMu.Lock()
		d.triggerID = id
		d.sendMu.Unlock()
	}
	return err
}

// Finish is called only after measurement, the resource/export barrier, and
// visitor late.Finish (which joins Notify). EXPORT can queue during child hold.
// the returned error and Receipt retain child failures even without artifacts.
func (d *postgresNativeTrace) Finish(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.finish.Do(func() {
		defer d.Close()
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		id, err := d.send(ctx, runtimetrace.Command{Kind: runtimetrace.Export})
		if err == nil {
			err = d.wait(ctx, id, runtimetrace.Export)
		}
		d.sendMu.Lock()
		triggerID := d.triggerID
		d.sendMu.Unlock()
		if triggerID != 0 {
			err = errors.Join(err, d.wait(ctx, triggerID, runtimetrace.Trigger))
		}
		d.mu.Lock()
		d.finishErr = errors.Join(d.err, err)
		d.mu.Unlock()
	})
	return d.finishErr
}

func (d *postgresNativeTrace) Receipt() *runtimetrace.Receipt {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.receipt
}

// Close aborts pipe ownership and joins the decoder, including failed Start.
// it does not signal/kill the native connector; the existing process owner does.
// this joins IPC only, not the child's abort snapshot/export. EOF requests those
// partial artifacts best-effort; stopping the process may interrupt that work.
func (d *postgresNativeTrace) Close() {
	if d == nil {
		return
	}
	d.close.Do(func() {
		d.cancel()
		d.AfterStart()
		_ = d.commands.Close()
		_ = d.replies.Close()
		<-d.done
	})
}
