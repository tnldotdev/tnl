// Package background owns the native child process and local control socket for
// an ordinary background job. commands supply startup facts and presentation.
package background

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type Kind string

const (
	KindPublish   Kind = "publish"
	KindConnect   Kind = "connect"
	KindPublisher Kind = "publisher"
)

func (k Kind) valid() bool {
	return k == KindPublish || k == KindConnect || k == KindPublisher
}

type State string

const (
	StateStarting     State = "starting"
	StateReady        State = "ready"
	StateReconnecting State = "reconnecting"
	StateStopping     State = "stopping"
	StateStopped      State = "stopped"
)

// Readiness is reported by the serving operation, not inferred by the launcher.
// Profile carries the connector's own shape. Profile, ConnectCommand, and
// GuestEntryURL go only to the launcher, not status and list.
type Readiness struct {
	Address        string          `json:"address,omitempty"`
	Target         string          `json:"target,omitempty"`
	TunnelID       string          `json:"tunnel_id,omitempty"`
	ServiceID      string          `json:"service_id,omitempty"`
	ConnectCommand []string        `json:"connect_command,omitempty"`
	Profile        json.RawMessage `json:"profile,omitempty"`
	GuestEntryURL  string          `json:"guest_entry_url,omitempty"`
}

type Entry struct {
	JobID    string `json:"job_id"`
	StateDir string `json:"-"`
	Kind     Kind   `json:"kind"`
	State    State  `json:"state"`
	PID      int    `json:"pid"`
	Readiness
}

func (e Entry) valid(id string) bool {
	return e.JobID == id && e.Kind.valid() && e.PID > 0
}

// ErrNotFound means there is no reachable socket owner for the exact ID in this
// state directory. it is not confirmation that a stop request was processed.
var ErrNotFound = errors.New("background job not found")

const (
	statusRequest = '?'
	stopRequest   = '!'
	controlLimit  = 2 * time.Second
	confirmLimit  = 250 * time.Millisecond
	maxFrame      = 128 << 10
)

type controlRequest struct {
	JobID     string `json:"job_id"`
	Operation byte   `json:"operation"`
}

func Status(ctx context.Context, stateDir, id string) (Entry, error) {
	return request(ctx, stateDir, id, statusRequest)
}

// Stop asks the exact socket owner to cancel its work. if the operation joins
// promptly it also confirms StateStopped on that connection; otherwise the
// acknowledgement reports StateStopping. a lost socket proves neither.
func Stop(ctx context.Context, stateDir, id string) (Entry, error) {
	return request(ctx, stateDir, id, stopRequest)
}

func List(ctx context.Context, stateDir string) ([]Entry, error) {
	result := []Entry{}
	root, err := selectStateRoot(stateDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	dir, err := scopeDirectory(root, false)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		if !opaqueid.Valid(item.Name(), opaqueid.JobPrefix) {
			continue
		}
		entry, err := requestAt(ctx, root, dir, item.Name(), statusRequest)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, nil
}

func request(ctx context.Context, stateDir, id string, operation byte) (Entry, error) {
	if !opaqueid.Valid(id, opaqueid.JobPrefix) {
		return Entry{}, failure.Wrap("select background job", failure.InvalidTunnelFlags, errors.New("invalid background job ID"))
	}
	root, err := selectStateRoot(stateDir, false)
	if err != nil {
		return Entry{}, lookupError(err)
	}
	dir, err := scopeDirectory(root, false)
	if err != nil {
		return Entry{}, lookupError(err)
	}
	return requestAt(ctx, root, dir, id, operation)
}

func lookupError(err error) error {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return failure.Wrap("find background job", failure.BackgroundNotFound, ErrNotFound)
	}
	return err
}

func requestAt(ctx context.Context, root, dir, id string, operation byte) (Entry, error) {
	dir, path := jobPaths(dir, id)
	if err := privateDirectory(dir, false); err != nil {
		return Entry{}, lookupError(err)
	}
	if err := privateSocket(path); err != nil {
		return Entry{}, lookupError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, controlLimit)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Entry{}, lookupError(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stopClosing := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClosing()
	if err := writeFrame(conn, controlRequest{JobID: id, Operation: operation}); err != nil {
		return Entry{}, controlError(ctx, err)
	}
	reader := frameReader(conn)
	var entry Entry
	if err := readFrame(reader, &entry); err != nil {
		return Entry{}, controlError(ctx, err)
	}
	if opaqueid.Valid(entry.JobID, opaqueid.JobPrefix) && entry.JobID != id {
		return Entry{}, lookupError(os.ErrNotExist)
	}
	validState := entry.State == StateStopping ||
		operation == statusRequest && (entry.State == StateStarting || entry.State == StateReady || entry.State == StateReconnecting)
	if !entry.valid(id) || !validState {
		return Entry{}, controlError(ctx, errors.New("unexpected job status"))
	}
	entry.StateDir = root
	if operation == stopRequest {
		var confirmed Entry
		if err := readFrame(reader, &confirmed); err == nil && confirmed.valid(id) &&
			confirmed.State == StateStopped && confirmed.PID == entry.PID && confirmed.Kind == entry.Kind {
			entry.State = StateStopped
		}
	}
	return entry, nil
}

func controlError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return failure.Wrap("read background job status", failure.ServerResponseInvalid, err)
}

type controlKey struct{}

type jobControl struct {
	mu           sync.Mutex
	entry        Entry // identity and handoff state
	ready        bool  // first readiness receipt was prepared
	handoffLost  bool  // readiness disappeared before the receipt could be committed
	live         Readiness
	reconnecting bool
	runCtx       context.Context
	cancel       context.CancelFunc
	boot         net.Conn
	joined       chan struct{}
}

// Ready reports readiness from the serving operation. the first observation
// sends the startup receipt; later observations update only the job's live state.
// it is a no-op in an ordinary foreground operation.
func Ready(ctx context.Context, ready Readiness) error {
	c, ok := ctx.Value(controlKey{}).(*jobControl)
	if !ok {
		return nil
	}
	c.mu.Lock()
	err := c.runCtx.Err()
	if err == nil && c.entry.State == StateStopping {
		err = context.Canceled
	}
	if err != nil {
		started := c.ready
		c.mu.Unlock()
		if started {
			return nil
		}
		return err
	}
	entry := c.entry
	if ready.Address == "" && (entry.Kind == KindConnect || entry.Kind == KindPublish && len(ready.ConnectCommand) == 0) {
		c.mu.Unlock()
		return errors.New("background job readiness is missing its address")
	}
	c.live = Readiness{Address: ready.Address, Target: ready.Target, TunnelID: ready.TunnelID, ServiceID: ready.ServiceID}
	c.reconnecting = false
	if c.ready {
		c.mu.Unlock()
		return nil
	}
	c.ready = true
	c.mu.Unlock()

	entry.Readiness = ready
	entry.State = StateReady
	if err := writeFrame(c.boot, startupReply{Entry: entry}); err != nil {
		c.cancel()
		return err
	}
	return nil
}

// Reconnecting marks lost readiness without starting a new job or sending a
// second receipt. before the first ready observation the job is still starting.
func Reconnecting(ctx context.Context) {
	c, ok := ctx.Value(controlKey{}).(*jobControl)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ready && c.entry.State != StateStopping && c.runCtx.Err() == nil {
		c.reconnecting = true
		if c.entry.State == StateStarting {
			c.handoffLost = true
		}
	}
}

func (c *jobControl) snapshot() Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runCtx.Err() != nil {
		c.entry.State = StateStopping
	}
	entry := c.entry
	if entry.State == StateReady {
		entry.Readiness = c.live
		if c.reconnecting {
			entry.State = StateReconnecting
			entry.Address = ""
		}
	}
	return entry
}

func (c *jobControl) stop() Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry.State = StateStopping
	return c.entry
}

func (c *jobControl) serve(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		c.respond(conn)
		_ = conn.Close()
	}
}

func (c *jobControl) respond(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(controlLimit))
	var request controlRequest
	if err := readFrame(bufio.NewReaderSize(conn, 128), &request); err != nil {
		return
	}
	// on a case-insensitive filesystem a differently cased ID may dial this
	// socket. verify the exact handle before acting, not just in the client.
	current := c.snapshot()
	if request.JobID != current.JobID {
		_ = writeFrame(conn, current)
		return
	}
	switch request.Operation {
	case statusRequest:
		_ = writeFrame(conn, current)
	case stopRequest:
		entry := c.stop()
		err := writeFrame(conn, entry)
		c.cancel()
		if err != nil {
			return
		}
		timer := time.NewTimer(confirmLimit)
		defer timer.Stop()
		select {
		case <-c.joined:
			entry.State = StateStopped
			_ = writeFrame(conn, entry)
		case <-timer.C:
		}
	}
}

func frameReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, maxFrame)
}

func readFrame(reader *bufio.Reader, value any) error {
	data, err := reader.ReadSlice('\n')
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return errors.New("invalid background job message")
	}
	return nil
}

func writeFrame(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("invalid background job message")
	}
	if len(data) >= maxFrame {
		return errors.New("background job message exceeds size limit")
	}
	if n, err := w.Write(append(data, '\n')); err != nil {
		return err
	} else if n != len(data)+1 {
		return io.ErrShortWrite
	}
	return nil
}
