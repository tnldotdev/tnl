package muxsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	quic "github.com/quic-go/quic-go"
)

// preserve explicit nil and empty children, unlike errors.Join.
type normalCloseJoined []error

func (normalCloseJoined) Error() string     { return "joined close fixture" }
func (e normalCloseJoined) Unwrap() []error { return e }
func (normalCloseJoined) Is(error) bool     { panic("normal close classification called Is") }
func (normalCloseJoined) As(any) bool       { panic("normal close classification called As") }

type normalCloseWrapped struct{ cause error }

func (normalCloseWrapped) Error() string   { return "wrapped close fixture" }
func (e normalCloseWrapped) Unwrap() error { return e.cause }
func (normalCloseWrapped) Is(error) bool   { panic("normal close classification called Is") }
func (normalCloseWrapped) As(any) bool     { panic("normal close classification called As") }

type normalCloseOpaque struct{}

func (normalCloseOpaque) Error() string { return "opaque close fixture" }
func (normalCloseOpaque) Is(error) bool { panic("normal close classification called Is") }
func (normalCloseOpaque) As(any) bool   { panic("normal close classification called As") }

type normalCloseTimeout struct{ cause error }

func (normalCloseTimeout) Error() string   { return "independent network timeout" }
func (normalCloseTimeout) Timeout() bool   { return true }
func (normalCloseTimeout) Temporary() bool { return false }
func (e normalCloseTimeout) Unwrap() error { return e.cause }

var _ net.Error = normalCloseTimeout{}

func TestNormalSessionCloseOnlyRequiresEveryLeafToBeNormal(t *testing.T) {
	local, remote := &quic.ApplicationError{}, &quic.ApplicationError{Remote: true}
	var absent *quic.ApplicationError
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"closed session", ErrClosed, true},
		{"closed socket", net.ErrClosed, true},
		{"local application code zero", local, true},
		{"remote application code zero", remote, true},
		{"normalized local code zero", errors.Join(ErrClosed, local), true},
		{"normalized remote code zero", errors.Join(ErrClosed, remote), true},
		{"both exact sentinels", errors.Join(ErrClosed, net.ErrClosed), true},
		{"mixed normal leaves", normalCloseJoined{ErrClosed, local, net.ErrClosed, remote}, true},
		{"nested normal leaves", normalCloseWrapped{normalCloseJoined{
			fmt.Errorf("accept stream: %w", errors.Join(ErrClosed, local)),
			normalCloseWrapped{normalCloseJoined{net.ErrClosed, remote}},
		}}, true},
		{"join discards nil inputs", errors.Join(nil, ErrClosed, nil), true},
		{"empty join", normalCloseJoined{}, false},
		{"nil join", normalCloseJoined(nil), false},
		{"explicit nil child", normalCloseJoined{ErrClosed, nil}, false},
		{"nested empty join", normalCloseJoined{ErrClosed, normalCloseJoined{}}, false},
		{"nil single unwrap", normalCloseWrapped{}, false},
		{"nil application error", absent, false},
		{"joined nil application error", normalCloseJoined{ErrClosed, absent}, false},
		{"sentinel text is not identity", errors.New(ErrClosed.Error()), false},
		{"opaque matching hooks are not identity", normalCloseOpaque{}, false},
		{"local nonzero application error", &quic.ApplicationError{ErrorCode: 17}, false},
		{"remote nonzero application error", &quic.ApplicationError{Remote: true, ErrorCode: 17}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalSessionCloseOnly(test.err); got != test.want {
				t.Fatalf("normal close = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNormalSessionCloseOnlyPreservesIndependentJoinedCauses(t *testing.T) {
	application := &quic.ApplicationError{}
	normal := errors.Join(ErrClosed, application)
	for _, test := range []struct {
		name  string
		cause error
	}{
		{"EOF", io.EOF},
		{"unexpected EOF", io.ErrUnexpectedEOF},
		{"cancellation", context.Canceled},
		{"deadline", context.DeadlineExceeded},
		{"short write", io.ErrShortWrite},
		{"physical cleanup failure", errors.New("owned UDP close failed")},
		{"classified physical cleanup failure", &QUICTransportCloseError{Err: net.ErrClosed}},
		{"local application reset", &quic.ApplicationError{ErrorCode: 17}},
		{"remote application reset", &quic.ApplicationError{Remote: true, ErrorCode: 17}},
		{"local stream code zero", &quic.StreamError{}},
		{"remote stream code zero", &quic.StreamError{Remote: true}},
		{"local stream reset", &quic.StreamError{ErrorCode: 17}},
		{"remote stream reset", &quic.StreamError{Remote: true, ErrorCode: 17}},
		{"transport failure", &quic.TransportError{Remote: true, ErrorCode: 1}},
		{"idle timeout", &quic.IdleTimeoutError{}},
		{"handshake timeout", &quic.HandshakeTimeoutError{}},
		{"stateless reset", &quic.StatelessResetError{}},
		{"version negotiation failure", &quic.VersionNegotiationError{}},
		{"network timeout wrapping closed socket", normalCloseTimeout{net.ErrClosed}},
		{"network timeout wrapping closed session", normalCloseTimeout{ErrClosed}},
		{"network timeout wrapping normal application close", normalCloseTimeout{application}},
		{"network operation timeout wrapping closed socket", &net.OpError{
			Op: "read", Net: "udp", Err: normalCloseTimeout{net.ErrClosed},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if NormalSessionCloseOnly(test.cause) {
				t.Fatal("independent failure classified as normal closure")
			}
			for _, shape := range []struct {
				name string
				err  error
			}{
				{"normal first", errors.Join(normal, test.cause)},
				{"failure first", errors.Join(test.cause, normal)},
				{"nested", fmt.Errorf("retired dispatcher: %w", errors.Join(normal,
					fmt.Errorf("owned cleanup: %w", test.cause)))},
			} {
				t.Run(shape.name, func(t *testing.T) {
					if NormalSessionCloseOnly(shape.err) {
						t.Fatal("normal close hid an independent joined failure")
					}
					var retained *quic.ApplicationError
					if !errors.Is(shape.err, test.cause) || !errors.Is(shape.err, ErrClosed) ||
						!errors.Is(shape.err, application) || !errors.As(shape.err, &retained) {
						t.Fatal("classification changed the original error tree")
					}
				})
			}
		})
	}
}

func TestNormalSessionCloseOnlyDoesNotUseCompoundMatchingHooks(t *testing.T) {
	normal := errors.Join(ErrClosed, &quic.ApplicationError{Remote: true})
	failure := errors.New("independent close failed")
	for _, err := range []error{
		normalCloseJoined{normal, failure},
		normalCloseJoined{failure, normal},
		normalCloseWrapped{errors.Join(normal, failure)},
		normalCloseJoined{normalCloseWrapped{normal}, normalCloseWrapped{failure}},
	} {
		if NormalSessionCloseOnly(err) {
			t.Fatal("compound closure matching hid an independent cause")
		}
	}
}
