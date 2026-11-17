package muxsession

import (
	"os"

	yamux "github.com/libp2p/go-yamux/v5"
)

// StreamDeadlineOnly recognizes exact native stream i/o deadlines without
// broadening arbitrary net.Error timeouts or cancellation into socket deadlines.
// it grants neither cancellation provenance nor retry permission.
func StreamDeadlineOnly(err error) bool {
	if err == os.ErrDeadlineExceeded || err == yamux.ErrTimeout {
		return true
	}
	switch wrapped := err.(type) {
	case *QUICTransportCloseError:
		return false
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !StreamDeadlineOnly(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return StreamDeadlineOnly(wrapped.Unwrap())
	default:
		return false
	}
}
