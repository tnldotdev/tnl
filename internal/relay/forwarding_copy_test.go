package relay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

type diagnosticCopyConn struct {
	net.Conn
	read, write           func([]byte) (int, error)
	close                 func() error
	reads, writes, closes atomic.Int32
}

func (c *diagnosticCopyConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.read(p)
}

func (c *diagnosticCopyConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.write(p)
}

func (c *diagnosticCopyConn) Close() error {
	c.closes.Add(1)
	if c.close != nil {
		return c.close()
	}
	return nil
}

type diagnosticHalfConn struct {
	*diagnosticCopyConn
	halfErr error
	halves  atomic.Int32
}

func (c *diagnosticHalfConn) CloseWrite() error {
	c.halves.Add(1)
	return c.halfErr
}

type diagnosticReadHalfConn struct {
	*diagnosticHalfConn
	readErr error
}

func (c *diagnosticReadHalfConn) CloseRead() error { return c.readErr }

type diagnosticResetHalfConn struct {
	*diagnosticHalfConn
	code uint32
}

func (c *diagnosticResetHalfConn) Reset(code uint32) error { c.code = code; return nil }

func copyOperationMarkers(err error) []*copyOperationError {
	var result []*copyOperationError
	var walk func(error)
	walk = func(err error) {
		if err == nil {
			return
		}
		if step, ok := err.(*copyOperationError); ok {
			result = append(result, step)
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range e.Unwrap() {
				walk(child)
			}
		case interface{ Unwrap() error }:
			walk(e.Unwrap())
		}
	}
	walk(err)
	return result
}

func requireCopyMarker(t *testing.T, err, original error, operation, endpoint, direction string) {
	t.Helper()
	count := 0
	for _, step := range copyOperationMarkers(err) {
		if step.Unwrap() != original {
			continue
		}
		op, end, dir := step.ForwardingCopyOperation()
		if op != operation || end != endpoint || dir != direction {
			t.Fatal("copy marker changed the returning call", op, end, dir)
		}
		count++
	}
	if count != 1 || !errors.Is(err, original) {
		t.Fatal("copy marker lost or duplicated the original failure", count)
	}
}

func TestRelayCopyOperationPartialIOAndHalfClosePreserveOriginalBehavior(t *testing.T) {
	for _, endpoint := range []string{"ingress", "publisher"} {
		for _, operation := range []string{"read", "write", "half_close"} {
			t.Run(endpoint+"/"+operation, func(t *testing.T) {
				native := &quic.StreamError{StreamID: 5, ErrorCode: 0, Remote: true}
				original := failure.Wrap("forward through relay", failure.ServerRelayFailed, native)
				type outcome struct {
					result streamcopy.Result
					err    error
					data   [2]string
					calls  [2][4]int32
				}
				run := func(observe bool) outcome {
					var reads sync.WaitGroup
					reads.Add(2)
					var data [2]bytes.Buffer
					var connections [2]*diagnosticHalfConn
					for i := range connections {
						input := []byte("request")
						if i == 1 {
							input = []byte("response")
						}
						selected := (i == 0) == (endpoint == "ingress")
						base := &diagnosticCopyConn{}
						base.read = func(p []byte) (int, error) {
							reads.Done()
							reads.Wait()
							n := copy(p, input)
							if selected && operation == "read" {
								return n, original
							}
							return n, io.EOF
						}
						base.write = func(p []byte) (int, error) {
							if selected && operation == "write" {
								n, _ := data[i].Write(p[:3])
								return n, original
							}
							return data[i].Write(p)
						}
						connections[i] = &diagnosticHalfConn{diagnosticCopyConn: base}
						if selected && operation == "half_close" {
							connections[i].halfErr = original
						}
					}
					var left, right net.Conn = connections[0], connections[1]
					if observe {
						var observed bool
						left, right, observed = copyDiagnosticArguments(left, right)
						if !observed {
							t.Fatal("known method sets were not observed")
						}
					}
					result, err := streamcopy.Copy(left, right)
					got := outcome{result: result, err: err}
					for i, c := range connections {
						got.data[i] = data[i].String()
						got.calls[i] = [4]int32{c.reads.Load(), c.writes.Load(), c.closes.Load(), c.halves.Load()}
					}
					return got
				}
				plain, marked := run(false), run(true)
				if plain.result != marked.result || plain.data != marked.data || plain.calls != marked.calls {
					t.Fatal("observation changed bytes or method calls", plain, marked)
				}
				want := streamcopy.Result{LeftToRight: 7, RightToLeft: 8}
				wantData := [2]string{"response", "request"}
				if operation == "write" {
					if endpoint == "publisher" {
						want.LeftToRight = 3
						wantData[1] = "req"
					} else {
						want.RightToLeft = 3
						wantData[0] = "res"
					}
				}
				if marked.result != want || marked.data != wantData || marked.calls[0][2] != 1 || marked.calls[1][2] != 1 {
					t.Fatal("partial bytes or abort close counts changed", marked)
				}
				direction := "visitor_to_publisher"
				if (operation == "read") == (endpoint == "publisher") {
					direction = "publisher_to_visitor"
				}
				requireCopyMarker(t, marked.err, original, operation, endpoint, direction)
				var got *quic.StreamError
				if !errors.As(marked.err, &got) || got != native || !failure.Only(marked.err, native) ||
					!failure.Only(plain.err, native) || failure.Only(marked.err, net.ErrClosed) {
					t.Fatal("observation changed native identity or all-cause classification")
				}
				reason, ok := failure.ReasonOf(marked.err)
				if !ok || reason != failure.ServerRelayFailed {
					t.Fatal("observation changed operational reason")
				}
			})
		}
	}
}

func TestRelayCopyOperationCopySentinelContrasts(t *testing.T) {
	wrappedEOF := fmt.Errorf("wrapped: %w", io.EOF)
	wrappedUnsupported := fmt.Errorf("wrapped: %w", errors.ErrUnsupported)
	for _, test := range []struct {
		name       string
		read, half error
		noHalf     bool
		wantErr    error
	}{
		{name: "clean EOF absent half-close", read: io.EOF, noHalf: true},
		{name: "clean EOF exact unsupported half-close", read: io.EOF, half: errors.ErrUnsupported},
		{name: "wrapped EOF is not clean EOF", read: wrappedEOF, wantErr: wrappedEOF},
		{name: "unsupported read is a failure", read: errors.ErrUnsupported, wantErr: errors.ErrUnsupported},
		{name: "wrapped unsupported half-close is a failure", read: io.EOF, half: wrappedUnsupported, wantErr: wrappedUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := bytes.NewBufferString("payload")
			var downloaded bytes.Buffer
			left := &diagnosticCopyConn{read: reader.Read, write: downloaded.Write}
			right := &diagnosticCopyConn{
				read:  func([]byte) (int, error) { return 0, test.read },
				write: func(p []byte) (int, error) { return len(p), nil },
			}
			var originalLeft, originalRight net.Conn = left, right
			if !test.noHalf {
				// only ingress receives the publisher's EOF and this half-close.
				originalLeft = &diagnosticHalfConn{diagnosticCopyConn: left, halfErr: test.half}
				originalRight = &diagnosticHalfConn{diagnosticCopyConn: right}
			}
			a, b, observed := copyDiagnosticArguments(originalLeft, originalRight)
			if !observed {
				t.Fatal("sentinel fixture was not observed")
			}
			result, err := streamcopy.Copy(a, b)
			if result.LeftToRight != 7 || result.RightToLeft != 0 || downloaded.Len() != 0 ||
				(test.wantErr == nil) != (err == nil) || test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatal("observation changed Copy's sentinel handling or accounting", result, err)
			}
			wantCloses := int32(0)
			if test.wantErr != nil {
				wantCloses = 1
				op, endpoint, direction := "read", "publisher", "publisher_to_visitor"
				if test.half != nil {
					op, endpoint = "half_close", "ingress"
				}
				requireCopyMarker(t, err, test.wantErr, op, endpoint, direction)
			}
			if left.closes.Load() != wantCloses || right.closes.Load() != wantCloses {
				t.Fatal("sentinel handling changed abort closes")
			}
		})
	}
}

func TestRelayCopyOperationKeepsSimultaneousFailuresAbortAndFinalCleanupSeparate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		readFailure := &quic.StreamError{StreamID: 1, ErrorCode: 0, Remote: true}
		writeFailure := errors.New("private write failure")
		abort := [2]error{errors.New("private ingress abort"), errors.New("private publisher abort")}
		final := [2]error{errors.New("private ingress final"), errors.New("private publisher final")}
		var starts sync.WaitGroup
		starts.Add(2)
		var connections [2]*diagnosticCopyConn
		var order []int
		var mu sync.Mutex
		for i := range connections {
			c := &diagnosticCopyConn{}
			c.read = func(p []byte) (int, error) {
				starts.Done()
				starts.Wait()
				n := copy(p, "payload")
				if i == 0 {
					return n, readFailure
				}
				return n, io.EOF
			}
			c.write = func(p []byte) (int, error) {
				if i == 0 {
					return 3, writeFailure
				}
				return len(p), nil
			}
			c.close = func() error {
				mu.Lock()
				defer mu.Unlock()
				order = append(order, i)
				if c.closes.Load() == 1 {
					return abort[i]
				}
				return final[i]
			}
			connections[i] = c
		}
		left, right, observed := copyDiagnosticArguments(connections[0], connections[1])
		if !observed {
			t.Fatal("base connections were not observed")
		}
		copied, err := streamcopy.Copy(left, right)
		if copied.LeftToRight != 7 || copied.RightToLeft != 3 {
			t.Fatal("simultaneous failures lost partial accounting", copied)
		}
		requireCopyMarker(t, err, readFailure, "read", "ingress", "visitor_to_publisher")
		requireCopyMarker(t, err, writeFailure, "write", "ingress", "publisher_to_visitor")
		requireCopyMarker(t, err, abort[0], "copy_abort_close", "ingress", "not_applicable")
		requireCopyMarker(t, err, abort[1], "copy_abort_close", "publisher", "not_applicable")
		if len(copyOperationMarkers(err)) != 4 || failure.Only(err, readFailure) {
			t.Fatal("simultaneous or independent abort failure was hidden")
		}
		diagnostic := ForwardingError{phase: "copy", copyResult: err, copyMethodsObserved: observed}
		// mirror the existing deferred original-object closes, publisher first.
		diagnostic.cleanup = errors.Join(connections[1].Close(), connections[0].Close())
		reported := diagnostic.finish(err)
		for _, cause := range final {
			if !errors.Is(reported, cause) || errors.Is(diagnostic.copyResult, cause) {
				t.Fatal("final cleanup crossed the copy result boundary")
			}
		}
		if len(copyOperationMarkers(diagnostic.cleanup)) != 0 ||
			!reflect.DeepEqual(order, []int{0, 1, 1, 0}) ||
			connections[0].closes.Load() != 2 || connections[1].closes.Load() != 2 {
			t.Fatal("observation marked final cleanup or changed close order", order)
		}
	})
}

func TestRelayCopyOperationAbortStillJoinsIdleDirection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initiating, idle := errors.New("private initiating read"), errors.New("private idle read")
		closed, joined := make(chan struct{}), make(chan struct{})
		left := &diagnosticCopyConn{read: func([]byte) (int, error) { return 0, initiating }}
		right := &diagnosticCopyConn{
			read: func([]byte) (int, error) {
				defer close(joined)
				<-closed
				return 0, idle
			},
			close: func() error { close(closed); return nil },
		}
		a, b, _ := copyDiagnosticArguments(left, right)
		copied, err := streamcopy.Copy(a, b)
		select {
		case <-joined:
		default:
			t.Fatal("copy returned without joining its idle direction")
		}
		requireCopyMarker(t, err, initiating, "read", "ingress", "visitor_to_publisher")
		requireCopyMarker(t, err, idle, "read", "publisher", "publisher_to_visitor")
		if copied != (streamcopy.Result{}) || left.closes.Load() != 1 || right.closes.Load() != 1 {
			t.Fatal("abort changed bytes or close counts")
		}
	})
}

func TestRelayCopyOperationPreservesExactSentinelsAndSafeFormatting(t *testing.T) {
	for _, original := range []error{nil, io.EOF, fmt.Errorf("wrapped: %w", io.EOF), errors.Join(io.EOF, net.ErrClosed),
		errors.ErrUnsupported, fmt.Errorf("wrapped: %w", errors.ErrUnsupported)} {
		c := &diagnosticHalfConn{diagnosticCopyConn: &diagnosticCopyConn{
			read:  func(p []byte) (int, error) { return copy(p, "abc"), original },
			write: func([]byte) (int, error) { return 2, original },
			close: func() error { return original },
		}, halfErr: original}
		arg, _, observed := copyDiagnosticArguments(c, c)
		if !observed {
			t.Fatal("known half-close method set was not observed")
		}
		var p [8]byte
		n, readErr := arg.Read(p[:])
		if n != 3 || string(p[:n]) != "abc" {
			t.Fatal("read result changed")
		}
		if original == nil || original == io.EOF {
			if readErr != original {
				t.Fatal("exact EOF or nil read was wrapped")
			}
		} else {
			requireCopyMarker(t, readErr, original, "read", "ingress", "visitor_to_publisher")
		}
		n, writeErr := arg.Write(p[:])
		if n != 2 {
			t.Fatal("partial write result changed")
		}
		halfErr := arg.(copyHalfCloser).CloseWrite()
		if original == nil || original == errors.ErrUnsupported {
			if halfErr != original {
				t.Fatal("exact unsupported or nil half-close was wrapped")
			}
		} else {
			requireCopyMarker(t, halfErr, original, "half_close", "ingress", "publisher_to_visitor")
		}
		if original == nil {
			if writeErr != nil || arg.Close() != nil {
				t.Fatal("nil was remapped")
			}
		} else {
			requireCopyMarker(t, writeErr, original, "write", "ingress", "publisher_to_visitor")
			requireCopyMarker(t, arg.Close(), original, "copy_abort_close", "ingress", "not_applicable")
		}
	}
	private := errors.New("https://private.invalid/secret")
	marker := &copyOperationError{cause: private, operation: copyRead, endpoint: copyIngress}
	for _, rendered := range []string{fmt.Sprint(marker), fmt.Sprintf("%+v", marker), fmt.Sprintf("%#v", marker)} {
		if strings.Contains(rendered, "private.invalid") || strings.Contains(rendered, "secret") {
			t.Fatal("operation marker formatted private cause text")
		}
	}
}

func TestRelayCopyOperationPreservesSupportedMethodSets(t *testing.T) {
	base := &diagnosticCopyConn{}
	half := &diagnosticHalfConn{diagnosticCopyConn: base}
	read := &diagnosticReadHalfConn{diagnosticHalfConn: half, readErr: errors.ErrUnsupported}
	reset := &diagnosticResetHalfConn{diagnosticHalfConn: half}
	for _, original := range []net.Conn{base, half, read, reset, &trackedConn{Conn: base}} {
		a, _, observed := copyDiagnosticArguments(original, base)
		if !observed {
			t.Fatal("supported profile was not observed", reflect.TypeOf(original))
		}
		before, after := reflect.TypeOf(original), reflect.TypeOf(a)
		if before.NumMethod() != after.NumMethod() {
			t.Fatal("adapter changed method count", before, after)
		}
		for i := range before.NumMethod() {
			method := before.Method(i)
			got, ok := after.MethodByName(method.Name)
			if !ok || method.Type.NumIn() != got.Type.NumIn() || method.Type.NumOut() != got.Type.NumOut() {
				t.Fatal("adapter changed a capability", method.Name)
			}
			for j := 1; j < method.Type.NumIn(); j++ {
				if method.Type.In(j) != got.Type.In(j) {
					t.Fatal("adapter changed capability input")
				}
			}
			for j := range method.Type.NumOut() {
				if method.Type.Out(j) != got.Type.Out(j) {
					t.Fatal("adapter changed capability output")
				}
			}
		}
	}
	a, _, _ := copyDiagnosticArguments(base, base)
	if _, ok := a.(copyHalfCloser); ok {
		t.Fatal("adapter installed absent CloseWrite")
	}
	a, _, _ = copyDiagnosticArguments(read, base)
	if a.(copyReadCloser).CloseRead() != errors.ErrUnsupported {
		t.Fatal("CloseRead was not delegated exactly")
	}
	a, _, _ = copyDiagnosticArguments(reset, base)
	if err := a.(copyResetter).Reset(17); err != nil || reset.code != 17 {
		t.Fatal("Reset was not delegated exactly")
	}
}

type diagnosticWriterToConn struct {
	*diagnosticCopyConn
	calls atomic.Int32
}

func (c *diagnosticWriterToConn) WriteTo(w io.Writer) (int64, error) {
	c.calls.Add(1)
	n, err := w.Write([]byte("fast-write"))
	return int64(n), err
}

type diagnosticReaderFromConn struct {
	*diagnosticCopyConn
	calls atomic.Int32
}

func (c *diagnosticReaderFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.calls.Add(1)
	return io.Copy(io.Writer(c.diagnosticCopyConn), r)
}

type diagnosticUnknownConn struct{ *diagnosticCopyConn }

func (*diagnosticUnknownConn) FutureCapability() {}

type diagnosticReadOnlyConn struct{ *diagnosticCopyConn }

func (*diagnosticReadOnlyConn) CloseRead() error { return nil }

func TestRelayCopyOperationFallbackRetainsBothObjectsAndFastPaths(t *testing.T) {
	for _, profile := range []string{"writer_to", "reader_from", "unknown", "unhandled_combination"} {
		for _, side := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", profile, side), func(t *testing.T) {
				var bases [2]*diagnosticCopyConn
				var received [2]bytes.Buffer
				for i := range bases {
					reader := bytes.NewBufferString("ordinary")
					bases[i] = &diagnosticCopyConn{read: reader.Read, write: received[i].Write}
				}
				args := [2]net.Conn{bases[0], bases[1]}
				var fastCalls *atomic.Int32
				switch profile {
				case "writer_to":
					c := &diagnosticWriterToConn{diagnosticCopyConn: bases[side]}
					args[side], fastCalls = c, &c.calls
				case "reader_from":
					c := &diagnosticReaderFromConn{diagnosticCopyConn: bases[side]}
					args[side], fastCalls = c, &c.calls
				case "unknown":
					args[side] = &diagnosticUnknownConn{bases[side]}
				case "unhandled_combination":
					args[side] = &diagnosticReadOnlyConn{bases[side]}
				}
				left, right, observed := copyDiagnosticArguments(args[0], args[1])
				if observed || left != args[0] || right != args[1] {
					t.Fatal("fallback changed an original object or claimed observation")
				}
				result, err := streamcopy.Copy(left, right)
				want := [2]string{"ordinary", "ordinary"}
				if profile == "writer_to" {
					want[1-side] = "fast-write"
				}
				if err != nil || received[0].String() != want[0] || received[1].String() != want[1] ||
					result.LeftToRight != int64(len(want[1])) || result.RightToLeft != int64(len(want[0])) {
					t.Fatal("fallback changed fast-path bytes or accounting", result, err)
				}
				if fastCalls != nil && fastCalls.Load() != 1 {
					t.Fatal("fallback hid the original fast-path call")
				}
				if profile == "writer_to" && bases[side].reads.Load() != 0 {
					t.Fatal("fallback replaced WriterTo with Read")
				}
				for _, c := range bases {
					if c.closes.Load() != 0 {
						t.Fatal("clean fallback introduced abort close")
					}
				}
			})
		}
	}
}
