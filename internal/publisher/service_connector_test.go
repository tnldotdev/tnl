package publisher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type connectorAdapterAdmission struct {
	mu  sync.Mutex
	err error
}

func (a *connectorAdapterAdmission) SetupDeadline() time.Time {
	return time.Now().Add(10 * time.Second)
}
func (a *connectorAdapterAdmission) FinishSetup() error { return nil }
func (a *connectorAdapterAdmission) CheckUse(context.Context) (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Add(time.Minute), a.err
}
func (a *connectorAdapterAdmission) Stop() { a.mu.Lock(); defer a.mu.Unlock(); a.err = ErrEndpoint }

type connectorAdapterWire struct {
	net.Conn
	input                         *bytes.Reader
	reads, writes, halves, closes int
	afterRead                     func()
}

func (c *connectorAdapterWire) Read(p []byte) (int, error) {
	c.reads++
	n, err := c.input.Read(p)
	if c.afterRead != nil {
		c.afterRead()
	}
	return n, err
}
func (c *connectorAdapterWire) Write(p []byte) (int, error)       { c.writes++; return len(p), nil }
func (c *connectorAdapterWire) CloseWrite() error                 { c.halves++; return nil }
func (c *connectorAdapterWire) Close() error                      { c.closes++; return nil }
func (c *connectorAdapterWire) WriteTo(io.Writer) (int64, error)  { panic("unguarded WriterTo") }
func (c *connectorAdapterWire) ReadFrom(io.Reader) (int64, error) { panic("unguarded ReaderFrom") }

func TestConnectorServiceAdapterFencesEveryDispatchAndBufferedResult(t *testing.T) {
	a := new(connectorAdapterAdmission)
	raw := &connectorAdapterWire{input: bytes.NewReader([]byte("buffered"))}
	conn := &connectorServiceConn{conn: raw, ctx: t.Context(), admission: a}
	if _, ok := any(conn).(io.WriterTo); ok {
		t.Fatal("native adapter exposed WriterTo")
	}
	if _, ok := any(conn).(io.ReaderFrom); ok {
		t.Fatal("native adapter exposed ReaderFrom")
	}
	if _, err := io.Copy(conn, bytes.NewReader([]byte("authorized"))); err != nil {
		t.Fatal(err)
	}
	raw.afterRead = a.Stop
	var b [16]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, ErrEndpoint) {
		t.Fatal("late raw or TLS-buffered read escaped current use", n, err)
	}
	reads, writes := raw.reads, raw.writes
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("terminal stream entered another read")
	}
	if _, err := conn.Write([]byte("forbidden")); err == nil {
		t.Fatal("terminal stream entered another write")
	}
	if err := conn.CloseWrite(); err == nil {
		t.Fatal("terminal stream entered another half-close")
	}
	if raw.reads != reads || raw.writes != writes || raw.halves != 0 {
		t.Fatal("adapter dispatched after authority loss")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if raw.closes != 1 {
		t.Fatal("cleanup did not preserve first physical close")
	}
}
