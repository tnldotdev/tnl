package streamcopy

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	quic "github.com/quic-go/quic-go"
)

func TestNormalize(t *testing.T) {
	other := errors.New("other stream copy error")
	quicFailure := &quic.StreamError{ErrorCode: 1, Remote: true}
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil"},
		{name: "EOF", err: io.EOF},
		{name: "closed", err: net.ErrClosed},
		{name: "unsupported half-close", err: errors.ErrUnsupported},
		{
			name: "connection reset",
			err: &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{
				Syscall: "read", Err: syscall.ECONNRESET,
			}},
		},
		{
			name: "broken pipe",
			err: &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{
				Syscall: "write", Err: syscall.EPIPE,
			}},
		},
		{
			name: "disconnected half-close",
			err: &net.OpError{Op: "close", Net: "tcp", Err: &os.SyscallError{
				Syscall: "shutdown", Err: syscall.ENOTCONN,
			}},
		},
		{name: "other", err: other, want: other},
		{name: "normal QUIC cancel", err: &quic.StreamError{ErrorCode: 0, Remote: true}},
		{name: "QUIC error", err: quicFailure, want: quicFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalize(test.err)
			if test.want == nil && got != nil {
				t.Fatalf("normalize(%v) = %v, want nil", test.err, got)
			}
			if test.want != nil && !errors.Is(got, test.want) {
				t.Fatalf("normalize(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
