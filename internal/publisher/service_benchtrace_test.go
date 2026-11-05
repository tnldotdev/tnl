//go:build tnl_benchtrace

package publisher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

const serviceBenchTraceTestID = "vc_aaaaaaaaaaaaaaaaaaaaaa"

type serviceBenchTraceAdmission struct {
	*connectorAdapterAdmission
	id string
}

func (a *serviceBenchTraceAdmission) DiagnosticVisitorConnectionID() string { return a.id }

func newServiceBenchTraceAdmission() *serviceBenchTraceAdmission {
	return &serviceBenchTraceAdmission{connectorAdapterAdmission: new(connectorAdapterAdmission), id: serviceBenchTraceTestID}
}

type serviceBenchTraceWire struct {
	net.Conn
	read                           func([]byte) (int, error)
	write                          func([]byte) (int, error)
	reads, writes, halves, closes  int
	halfErr, closeErr, deadlineErr error
	deadlines                      [3]time.Time
	deadlineCalls                  [3]int
}

func (c *serviceBenchTraceWire) Read(p []byte) (int, error) {
	c.reads++
	if c.read != nil {
		return c.read(p)
	}
	if c.Conn != nil {
		return c.Conn.Read(p)
	}
	return 0, io.EOF
}

func (c *serviceBenchTraceWire) Write(p []byte) (int, error) {
	c.writes++
	if c.write != nil {
		return c.write(p)
	}
	if c.Conn != nil {
		return c.Conn.Write(p)
	}
	return len(p), nil
}

func (c *serviceBenchTraceWire) CloseWrite() error { c.halves++; return c.halfErr }
func (c *serviceBenchTraceWire) Close() error {
	c.closes++
	if c.closeErr != nil || c.Conn == nil {
		return c.closeErr
	}
	return c.Conn.Close()
}
func (c *serviceBenchTraceWire) SetDeadline(at time.Time) error {
	c.deadlineCalls[0]++
	c.deadlines[0] = at
	return c.deadlineErr
}
func (c *serviceBenchTraceWire) SetReadDeadline(at time.Time) error {
	c.deadlineCalls[1]++
	c.deadlines[1] = at
	return c.deadlineErr
}
func (c *serviceBenchTraceWire) SetWriteDeadline(at time.Time) error {
	c.deadlineCalls[2]++
	c.deadlines[2] = at
	return c.deadlineErr
}
func (*serviceBenchTraceWire) ReadFrom(io.Reader) (int64, error) { panic("bypassed Read/Write") }
func (*serviceBenchTraceWire) WriteTo(io.Writer) (int64, error)  { panic("bypassed Read/Write") }
func (*serviceBenchTraceWire) Unwrap() net.Conn                  { panic("unwrapped connection") }
func (*serviceBenchTraceWire) NetConn() net.Conn                 { panic("unwrapped connection") }
func (*serviceBenchTraceWire) SyscallConn() (syscall.RawConn, error) {
	panic("exposed raw descriptor")
}

func TestServiceBenchTraceUnmappedAndRecorderOff(t *testing.T) {
	client, target := new(serviceBenchTraceWire), new(serviceBenchTraceWire)
	for _, admission := range []ServiceConnectorAdmission{nil, NativeAdmissionFixture{}, &serviceBenchTraceAdmission{}} {
		left, right := serviceBenchTraceCopy(admission, client, target)
		if left != client || right != target {
			t.Fatal("missing diagnostic identity invented a mapping")
		}
	}
	admission := newServiceBenchTraceAdmission()
	left, right := serviceBenchTraceCopy(admission, client, target)
	if left == client || right == target {
		t.Fatal("mapped warm stream must be wrapped before recorder arming")
	}
	if trace.IsEnabled() {
		t.Skip("allocation checks require an inactive recorder")
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		_, _ = serviceBenchTraceCopy(admission, client, target)
	}); allocations > 2 {
		t.Fatalf("warm composition allocated more than its two wrappers: %g", allocations)
	}
	buffer := make([]byte, 8)
	if allocations := testing.AllocsPerRun(1000, func() {
		_, _ = left.Read(buffer)
		_, _ = right.Write(buffer)
	}); allocations != 0 {
		t.Fatalf("inactive recorder allocated per byte-copy call: %g", allocations)
	}
}

func TestServiceBenchTracePreservesConnectionOperations(t *testing.T) {
	readErr, writeErr := errors.New("private read cause"), errors.New("private write cause")
	deadlineErr, closeErr := errors.New("deadline cause"), errors.New("close cause")
	base, peer := net.Pipe()
	defer base.Close()
	defer peer.Close()
	raw := &serviceBenchTraceWire{Conn: base, deadlineErr: deadlineErr, closeErr: closeErr,
		read:  func(p []byte) (int, error) { return copy(p, "secret"), readErr },
		write: func([]byte) (int, error) { return 2, writeErr }}
	conn, _ := serviceBenchTraceCopy(newServiceBenchTraceAdmission(), raw, raw)
	buffer := make([]byte, 16)
	if n, err := conn.Read(buffer); n != 6 || err != readErr || string(buffer[:n]) != "secret" || raw.reads != 1 {
		t.Fatalf("read was not delegated exactly once: n=%d error=%v reads=%d", n, err, raw.reads)
	}
	if n, err := conn.Write(buffer); n != 2 || err != writeErr || raw.writes != 1 {
		t.Fatalf("write was not delegated exactly once: n=%d error=%v writes=%d", n, err, raw.writes)
	}
	for index, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		at := time.Now().Add(time.Duration(index) * time.Second)
		if err := set(at); err != deadlineErr || raw.deadlines[index] != at || raw.deadlineCalls[index] != 1 {
			t.Fatalf("deadline %d changed: %v", index, err)
		}
	}
	if conn.LocalAddr() != base.LocalAddr() || conn.RemoteAddr() != base.RemoteAddr() || conn.Close() != closeErr || raw.closes != 1 {
		t.Fatal("address or physical close delegation changed")
	}
	for _, halfErr := range []error{nil, errors.ErrUnsupported, fmt.Errorf("wrapped: %w", errors.ErrUnsupported), closeErr} {
		raw.halfErr = halfErr
		before := raw.halves
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != halfErr || raw.halves != before+1 {
			t.Fatalf("half-close changed exact result: %v want %v", err, halfErr)
		}
	}
	unsupported, _ := serviceBenchTraceCopy(newServiceBenchTraceAdmission(), base, peer)
	if err := unsupported.(interface{ CloseWrite() error }).CloseWrite(); err != errors.ErrUnsupported {
		t.Fatalf("missing half-close must return exact ErrUnsupported: %v", err)
	}
	for _, wrapped := range []net.Conn{conn, unsupported} {
		if _, ok := wrapped.(io.ReaderFrom); ok {
			t.Fatal("exposed ReaderFrom")
		}
		if _, ok := wrapped.(io.WriterTo); ok {
			t.Fatal("exposed WriterTo")
		}
		if _, ok := wrapped.(interface{ Unwrap() net.Conn }); ok {
			t.Fatal("exposed Unwrap")
		}
		if _, ok := wrapped.(interface{ NetConn() net.Conn }); ok {
			t.Fatal("exposed NetConn")
		}
		if _, ok := wrapped.(syscall.Conn); ok {
			t.Fatal("exposed raw descriptor")
		}
	}
}

func TestServiceBenchTraceCannotBypassAdmission(t *testing.T) {
	t.Run("denied before dispatch", func(t *testing.T) {
		a := newServiceBenchTraceAdmission()
		a.Stop()
		raw := &connectorAdapterWire{input: bytes.NewReader([]byte("forbidden"))}
		gate := &connectorServiceConn{conn: raw, ctx: t.Context(), admission: a}
		client, target := serviceBenchTraceCopy(a, gate, gate)
		recorder := startServiceBenchTraceRecorder(t)
		for _, conn := range []net.Conn{client, target} {
			if n, err := conn.Read(make([]byte, 16)); n != 0 || err != ErrEndpoint {
				t.Fatal("denied read escaped", n, err)
			}
			if n, err := io.Copy(conn, strings.NewReader("forbidden")); n != 0 || !errors.Is(err, ErrEndpoint) {
				t.Fatal("denied write escaped", n, err)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != ErrEndpoint {
				t.Fatal("denied half-close escaped", err)
			}
			_ = conn.Close()
		}
		if raw.reads != 0 || raw.writes != 0 || raw.halves != 0 || raw.closes != 1 {
			t.Fatalf("diagnostics bypassed the gate or changed joined cleanup: %+v", raw)
		}
		events, _ := snapshotServiceBenchTrace(t, recorder)
		ends := 0
		for _, event := range events {
			if strings.HasSuffix(event.category, ".end") {
				ends++
				if event.message != "visitor_connection_id="+serviceBenchTraceTestID+" bytes=0 error=true" {
					t.Fatalf("denied call reported raw bytes: %+v", event)
				}
			}
		}
		if ends != 4 {
			t.Fatalf("missing denied read/write results on both sides: %+v", events)
		}
	})
	t.Run("revoked after raw read", func(t *testing.T) {
		a := newServiceBenchTraceAdmission()
		raw := &connectorAdapterWire{input: bytes.NewReader([]byte("must-not-reach-target")), afterRead: a.Stop}
		target := new(serviceBenchTraceWire)
		clientGate := &connectorServiceConn{conn: raw, ctx: t.Context(), admission: a}
		targetGate := &connectorServiceConn{conn: target, ctx: t.Context(), admission: a}
		client, backend := serviceBenchTraceCopy(a, clientGate, targetGate)
		recorder := startServiceBenchTraceRecorder(t)
		result, err := streamcopy.Copy(client, backend)
		if !errors.Is(err, ErrEndpoint) || result.LeftToRight != 0 || target.writes != 0 || raw.reads != 1 {
			t.Fatalf("raw read released bytes after revocation: result=%+v error=%v target writes=%d raw reads=%d", result, err, target.writes, raw.reads)
		}
		events, parsed := snapshotServiceBenchTrace(t, recorder)
		for _, event := range events {
			if strings.Contains(event.category, ".write.") || strings.HasSuffix(event.category, ".end") && event.message != "visitor_connection_id="+serviceBenchTraceTestID+" bytes=0 error=true" {
				t.Fatalf("revoked raw read reported released bytes: %+v", event)
			}
		}
		if strings.Contains(parsed, "must-not-reach-target") {
			t.Fatal("revoked read payload leaked into trace")
		}
	})
}

func TestServiceBenchTraceRealCopyWorkerProgress(t *testing.T) {
	visitor, clientRaw := net.Pipe()
	targetRaw, database := net.Pipe()
	for _, conn := range []net.Conn{visitor, clientRaw, targetRaw, database} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	a := newServiceBenchTraceAdmission()
	clientGate := &connectorServiceConn{conn: &serviceBenchTraceWire{Conn: clientRaw}, ctx: t.Context(), admission: a}
	targetGate := &connectorServiceConn{conn: &serviceBenchTraceWire{Conn: targetRaw}, ctx: t.Context(), admission: a}
	observed, streamDone := observability.PublisherStream(t.Context(), targetGate)
	client, target := serviceBenchTraceCopy(a, clientGate, observed)
	recorder := startServiceBenchTraceRecorder(t)
	trace.Log(context.Background(), "publisher.benchtrace.test.caller", "caller")
	type outcome struct {
		result streamcopy.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := streamcopy.Copy(client, target); done <- outcome{result, err} }()
	request, response := "private-query-payload", "private-database-response"
	transfer := func(writer, reader net.Conn, data string) {
		t.Helper()
		written := make(chan error, 1)
		go func() { _, err := io.WriteString(writer, data); written <- err }()
		buffer := make([]byte, len(data))
		if _, err := io.ReadFull(reader, buffer); err != nil || string(buffer) != data {
			t.Fatalf("transcript changed: %q %v", buffer, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
	transfer(visitor, database, request)
	transfer(database, visitor, response)
	_ = visitor.Close()
	_ = database.Close()
	select {
	case copied := <-done:
		streamDone(copied.err)
		if copied.err != nil || copied.result.LeftToRight != int64(len(request)) || copied.result.RightToLeft != int64(len(response)) {
			t.Fatalf("copy changed: %+v", copied)
		}
	case <-time.After(time.Second):
		t.Fatal("copy workers did not drain")
	}
	events, parsed := snapshotServiceBenchTrace(t, recorder)
	if strings.Contains(parsed, request) || strings.Contains(parsed, response) {
		t.Fatal("byte progress leaked payload")
	}
	message := regexp.MustCompile(`^visitor_connection_id=vc_aaaaaaaaaaaaaaaaaaaaaa bytes=[0-9]+ error=(true|false)$`)
	var caller int64
	for _, event := range events {
		if event.category == "publisher.benchtrace.test.caller" {
			caller = event.goroutine
			continue
		}
		if !message.MatchString(event.message) || event.task != 0 {
			t.Fatalf("unexpected trace fields or task: %+v", event)
		}
	}
	find := func(category string, count int, failed bool) serviceBenchTraceEvent {
		t.Helper()
		want := fmt.Sprintf("visitor_connection_id=%s bytes=%d error=%t", serviceBenchTraceTestID, count, failed)
		var found []serviceBenchTraceEvent
		for _, event := range events {
			if event.category == category && event.message == want {
				found = append(found, event)
			}
		}
		if len(found) != 1 {
			t.Fatalf("expected one %s %q, got %+v", category, want, found)
		}
		return found[0]
	}
	requestRead := find("publisher.visitor.read.end", len(request), false)
	requestWrite := find("publisher.target.write.end", len(request), false)
	responseRead := find("publisher.target.read.end", len(response), false)
	responseWrite := find("publisher.visitor.write.end", len(response), false)
	if caller == 0 || requestRead.goroutine == caller || responseRead.goroutine == caller || requestRead.goroutine != requestWrite.goroutine || responseRead.goroutine != responseWrite.goroutine || requestRead.goroutine == responseRead.goroutine {
		t.Fatal("progress did not identify the two actual copy workers")
	}
	for _, end := range []serviceBenchTraceEvent{requestRead, requestWrite, responseRead, responseWrite} {
		begin := strings.TrimSuffix(end.category, ".end") + ".begin"
		matched := false
		for _, event := range events[:end.index] {
			if event.category == begin && event.goroutine == end.goroutine {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("missing ordered copy begin before %+v", end)
		}
	}
}

func TestServiceBenchTraceArmingDuringReadIsCensored(t *testing.T) {
	if trace.IsEnabled() {
		t.Skip("requires no external trace consumer before arming")
	}
	for _, mode := range []string{"end-only", "begin-only"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			readErr := errors.New("secret raw error must not be logged")
			raw := &serviceBenchTraceWire{read: func(p []byte) (int, error) { close(entered); <-release; return copy(p, "private"), readErr }}
			client, _ := serviceBenchTraceCopy(newServiceBenchTraceAdmission(), raw, raw)
			var recorder *trace.FlightRecorder
			if mode == "begin-only" {
				recorder = startServiceBenchTraceRecorder(t)
			}
			done := make(chan error, 1)
			go func() {
				buffer := make([]byte, 16)
				n, err := client.Read(buffer)
				if n != 7 || err != readErr {
					done <- errors.New("read result changed")
					return
				}
				done <- nil
			}()
			<-entered
			var events []serviceBenchTraceEvent
			var parsed string
			if mode == "end-only" {
				recorder = startServiceBenchTraceRecorder(t)
				unblock()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				events, parsed = snapshotServiceBenchTrace(t, recorder)
			} else {
				events, parsed = snapshotServiceBenchTrace(t, recorder)
				unblock()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			wantCategory, wantCount, wantError := "publisher.visitor.read.begin", 0, false
			if mode == "end-only" {
				wantCategory, wantCount, wantError = "publisher.visitor.read.end", 7, true
			}
			want := fmt.Sprintf("visitor_connection_id=%s bytes=%d error=%t", serviceBenchTraceTestID, wantCount, wantError)
			if len(events) != 1 || events[0].category != wantCategory || events[0].message != want || strings.Contains(parsed, readErr.Error()) || strings.Contains(parsed, "private") {
				t.Fatalf("missing or invented censored boundary: %+v", events)
			}
		})
	}
}

type serviceBenchTraceEvent struct {
	goroutine, task   int64
	category, message string
	index             int
}

func startServiceBenchTraceRecorder(t *testing.T) *trace.FlightRecorder {
	t.Helper()
	recorder := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: time.Second, MaxBytes: 1 << 20})
	if err := recorder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(recorder.Stop)
	return recorder
}

func snapshotServiceBenchTrace(t *testing.T, recorder *trace.FlightRecorder) ([]serviceBenchTraceEvent, string) {
	t.Helper()
	var raw bytes.Buffer
	if _, err := recorder.WriteTo(&raw); err != nil {
		t.Fatal(err)
	}
	recorder.Stop()
	path := filepath.Join(t.TempDir(), "publisher.trace")
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "go", "tool", "trace", "-d=parsed", path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse real publisher trace: %v\n%s", err, output)
	}
	pattern := regexp.MustCompile(`(?m)^M=-?\d+ P=-?\d+ G=(\d+) Log Time=\d+ Task=(\d+) Category="(publisher\.[^"]*)" Message=(.*)$`)
	var events []serviceBenchTraceEvent
	for _, match := range pattern.FindAllStringSubmatch(string(output), -1) {
		goroutine, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		task, err := strconv.ParseInt(match[2], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		message, err := strconv.Unquote(match[4])
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, serviceBenchTraceEvent{goroutine: goroutine, task: task, category: match[3], message: message, index: len(events)})
	}
	return events, string(output)
}
