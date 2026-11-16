package muxsession

import (
	"net"

	quic "github.com/quic-go/quic-go"
)

// NormalSessionCloseOnly reports whether every cause is a normal session close.
// it does not change the error tree or accept cancellation, EOF, or independent
// failures that also match a closure sentinel.
func NormalSessionCloseOnly(err error) bool {
	if err == ErrClosed || err == net.ErrClosed {
		return true
	}
	switch cause := err.(type) {
	case *quic.ApplicationError:
		return cause != nil && cause.ErrorCode == 0
	case *QUICTransportCloseError, *quic.StreamError, *quic.TransportError,
		*quic.IdleTimeoutError, *quic.HandshakeTimeoutError, *quic.StatelessResetError,
		*quic.VersionNegotiationError:
		// these types carry failures even when they unwrap to net.ErrClosed.
		return false
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return false
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		causes := cause.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, child := range causes {
			if !NormalSessionCloseOnly(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return NormalSessionCloseOnly(cause.Unwrap())
	default:
		return false
	}
}
