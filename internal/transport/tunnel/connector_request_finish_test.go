package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorRequestFinishJoinsStartedRenewalAndPreventsRestart(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	cause := errors.New("renewal stopped")
	reader := NewConnectorRequestReader(left, nil, func(tunnelv1.ConnectorVisitorPermission) error { close(entered); <-release; return cause })
	reader.ContinueAfterTLSCloseNotify()
	written := make(chan error, 1)
	go func() {
		written <- tunnelv1.WriteConnectorRequestFrame(right, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestPermission, Permission: connectorRequestPermissionFixture()})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("renewal worker did not start")
	}
	finished := make(chan error, 1)
	go func() { finished <- reader.Finish() }()
	// physical close alone is not completion of a callback already entered.
	select {
	case err := <-finished:
		t.Fatal("finish returned before renewal joined", err)
	default:
	}
	close(release)
	if err := <-finished; !errors.Is(err, cause) {
		t.Fatal("finish lost renewal cause", err)
	}
	reader.ContinueAfterTLSCloseNotify()
	if err := reader.Finish(); !errors.Is(err, cause) {
		t.Fatal("repeat finish lost first completion", err)
	}
	<-written
	var b [1]byte
	if _, err := reader.Read(b[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatal("finished parser restarted", err)
	}
}

func TestConnectorRequestFinishBeforeContinuationDoesNotStartWorker(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	reader := NewConnectorRequestReader(left, nil, func(tunnelv1.ConnectorVisitorPermission) error { t.Error("late renewal ran"); return nil })
	if err := reader.Finish(); err != nil {
		t.Fatal(err)
	}
	reader.ContinueAfterTLSCloseNotify()
	reader.lifeMu.Lock()
	started := reader.started
	reader.lifeMu.Unlock()
	if started {
		t.Fatal("finish allowed a later continuation")
	}
}

type heldConnectorRequestRead struct {
	net.Conn
	entered, release, closed chan struct{}
}

func (c *heldConnectorRequestRead) Read(p []byte) (int, error) {
	close(c.entered)
	n, err := c.Conn.Read(p)
	<-c.release
	return n, err
}

func (c *heldConnectorRequestRead) Close() error {
	err := c.Conn.Close()
	close(c.closed)
	return err
}

func TestConnectorRequestFinishJoinsEnteredRead(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn := &heldConnectorRequestRead{Conn: left, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	release := sync.OnceFunc(func() { close(conn.release) })
	defer release()
	reader := NewConnectorRequestReader(conn, nil, nil)
	read := make(chan struct{})
	var readErr error
	go func() {
		defer close(read)
		var b [1]byte
		_, readErr = reader.Read(b[:])
	}()
	defer func() { release(); _ = reader.Finish(); <-read }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("ordinary raw read did not enter")
	}
	finished := make(chan error, 1)
	go func() { finished <- reader.Finish() }()
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("finish did not interrupt physical I/O")
	}
	select {
	case err := <-finished:
		t.Fatal("finish returned before the entered read joined", err)
	default:
	}
	release()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	<-read
	if !errors.Is(readErr, io.ErrClosedPipe) {
		t.Fatal("raw read lost its close cause", readErr)
	}
}
