package publisher

import (
	"context"
	"errors"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publishRunCleanup joins the workers started after the public URL server and
// connection manager. parent cancellation drains before transport cancellation;
// heartbeat and certificate failures close transports immediately.
type publishRunCleanup struct {
	parentCtx, sessionCtx context.Context
	cancelSession         context.CancelCauseFunc
	cancelTransports      context.CancelFunc
	connections           *publisherConnectionManager
	route                 *PublicURLServer
	config                Config
	setup                 controlv1.PublishRunSetup
	version               uint64
	heartbeatDone         <-chan error
	expirationDone        <-chan struct{}
	heartbeatStarted      bool
}

func (s *publishRunCleanup) finish(result error) error {
	s.cancelSession(nil)
	if s.heartbeatStarted && parentCanceledSession(s.parentCtx, s.sessionCtx) &&
		!errors.Is(result, controlclient.ErrStatusConflict) && !errors.Is(result, controlclient.ErrUnauthenticated) &&
		!errors.Is(result, errCertificateExpired) {
		result = s.drain(result)
	}
	s.cancelTransports()
	if s.heartbeatStarted {
		heartbeatErr := <-s.heartbeatDone
		select {
		case <-s.route.admission.completed:
			if errors.Is(heartbeatErr, context.Canceled) {
				heartbeatErr = nil
			}
		default:
		}
		result = errors.Join(result, heartbeatErr)
		if s.parentCtx.Err() == nil {
			cause := context.Cause(s.sessionCtx)
			if cause != nil && !errors.Is(cause, context.Canceled) {
				result = cause
			}
		}
	}
	s.connections.Close()
	<-s.expirationDone
	return result
}

func (s *publishRunCleanup) abort(err error) {
	s.cancelSession(err)
	s.cancelTransports()
	_ = s.route.Close()
}

func parentCanceledSession(parent, session context.Context) bool {
	return parent.Err() != nil && errors.Is(context.Cause(session), context.Cause(parent))
}

func (s *publishRunCleanup) drain(result error) error {
	if errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded) {
		result = nil
	}
	s.route.stopAdmissions()
	result = errors.Join(result, observe(s.config, Event{
		Type: EventDraining, PublicURLID: s.setup.PublicUrl.Id,
		Hostname: s.setup.PublicUrl.CanonicalHostname, PublishRunNumber: s.version,
	}))
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), s.config.DrainTime)
	connectionDrainErr := s.connections.Drain(drainCtx)
	publicURLDrainErr := s.route.Drain(drainCtx)
	cancelDrain()
	result = errors.Join(result, connectionDrainErr, publicURLDrainErr)
	select {
	case <-s.route.certificateExpiration():
		result = errors.Join(result, errCertificateExpired)
	default:
	}
	return result
}
