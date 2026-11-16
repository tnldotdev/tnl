package tunnel

import "github.com/tnldotdev/tnl/internal/transport/muxsession"

// ConnectorReplyEndedNormally reports a failed connector reply read whose session
// had already ended normally before owned cleanup. it describes this exact result,
// not a nested cause, and grants neither authority nor a retry by itself.
func ConnectorReplyEndedNormally(err error) bool {
	_, ok := err.(*connectorReplyEnd)
	return ok
}

type connectorReplyEnd struct{ err error }

func (e *connectorReplyEnd) Error() string { return e.err.Error() }
func (e *connectorReplyEnd) Unwrap() error { return e.err }

func connectorReplySessionEnded(transport muxsession.Session, operation error) bool {
	if !muxsession.NormalSessionCloseOnly(operation) {
		return false
	}
	select {
	case <-transport.Done():
		return muxsession.NormalSessionCloseOnly(transport.Err())
	default:
		return false
	}
}

func connectorReplyResult(err error, endedNormally bool) error {
	if err != nil && endedNormally {
		return &connectorReplyEnd{err: err}
	}
	return err
}
