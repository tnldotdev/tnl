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

type nativeAdapterAdmission struct {
	mu  sync.Mutex
	err error
}

func (a *nativeAdapterAdmission) SetupDeadline() time.Time { return time.Now().Add(10 * time.Second) }
func (a *nativeAdapterAdmission) FinishSetup() error       { return nil }
func (a *nativeAdapterAdmission) CheckUse(context.Context) (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Add(time.Minute), a.err
}
func (a *nativeAdapterAdmission) Stop() { a.mu.Lock(); defer a.mu.Unlock(); a.err = ErrEndpoint }

type nativeAdapterWire struct {
	net.Conn
	input                         *bytes.Reader
	reads, writes, halves, closes int
	afterRead                     func()
}

func (c *nativeAdapterWire) Read(p []byte) (int, error) {
	c.reads++
	n, err := c.input.Read(p)
	if c.afterRead != nil {
		c.afterRead()
	}
	return n, err
}
func (c *nativeAdapterWire) Write(p []byte) (int, error)       { c.writes++; return len(p), nil }
func (c *nativeAdapterWire) CloseWrite() error                 { c.halves++; return nil }
func (c *nativeAdapterWire) Close() error                      { c.closes++; return nil }
func (c *nativeAdapterWire) WriteTo(io.Writer) (int64, error)  { panic("unguarded WriterTo") }
func (c *nativeAdapterWire) ReadFrom(io.Reader) (int64, error) { panic("unguarded ReaderFrom") }

func TestNativeServiceAdapterFencesEveryDispatchAndBufferedResult(t *testing.T) {
	a := new(nativeAdapterAdmission)
	raw := &nativeAdapterWire{input: bytes.NewReader([]byte("buffered"))}
	conn := &nativeServiceConn{conn: raw, ctx: t.Context(), admission: a}
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
