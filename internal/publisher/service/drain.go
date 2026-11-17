package service

import (
	"io"
	"net"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// serviceDrainCloseOnly accepts a normal close, not a join that also contains
// rejection, cancellation, timeout, short-write, or independent cleanup errors.
func serviceDrainCloseOnly(err error, allowEOF bool) bool {
	if err == muxsession.ErrClosed || err == net.ErrClosed || allowEOF && err == io.EOF {
		return true
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		causes := cause.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, child := range causes {
			if !serviceDrainCloseOnly(child, allowEOF) {
				return false
			}
		}
		return true
	case *quic.ApplicationError:
		return cause != nil && cause.Remote && cause.ErrorCode == 0
	case interface{ Unwrap() error }:
		return serviceDrainCloseOnly(cause.Unwrap(), allowEOF)
	default:
		return false
	}
}
