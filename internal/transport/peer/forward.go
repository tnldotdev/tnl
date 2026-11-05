package peer

import (
	"context"
	"time"
)

// ForwardingRegistration owns both directions of one relay bridge. the publisher
// registration, destination admission fence, and replay windows survive connector
// replacement. each direction has one worker, joined by the role owner.
type ForwardingRegistration struct {
	publisher   forwardingCarrier
	connector   *CarrierSlot
	toPublisher replayWindow
	toConnector replayWindow
}

// forwarding carriers stamp the destination revision at transport admission,
// before any shared input queue. a dequeue cannot give old work a new carrier.
type forwardingCarrier interface {
	Carrier
	receiveForward(context.Context) (queuedFrame, error)
}

// ForwardToPublisher fences reads from removed connector carriers, but joins
// entered publisher sends within their original one-second timeout and authority.
// interrupting a retained publisher stream could leave a partial frame; any send
// error ends this direction so that the role owner retires the registration.
func (r *ForwardingRegistration) ForwardToPublisher(ctx context.Context) error {
	for {
		frame, revision, err := r.connector.receiveRevision(ctx)
		if err != nil {
			return err
		}
		if !r.toPublisher.acceptRevision(frame, revision) {
			continue
		}
		call, cancel := context.WithTimeout(ctx, time.Second)
		complete, err := r.connector.trackForward(call, revision)
		if complete == nil {
			cancel()
			if err != nil {
				return err
			}
			continue
		}
		err = r.publisher.Send(call, frame)
		cancel()
		complete()
		if err != nil {
			return err
		}
	}
}

// ForwardToConnector fences queued and entered sends into a removed connector
// carrier. unlike the retained publisher registration, that carrier is closed
// and never reused after replacement.
func (r *ForwardingRegistration) ForwardToConnector(ctx context.Context) error {
	for {
		frame, err := r.publisher.receiveForward(ctx)
		if err != nil {
			return err
		}
		if !r.toConnector.acceptRevision(frame.data, frame.revision) {
			continue
		}
		call, cancel := context.WithTimeout(ctx, time.Second)
		err = r.connector.sendRevision(call, frame.data, frame.revision)
		cancel()
		if err != nil {
			return err
		}
	}
}

// Close retires the publisher registration, not the slot or borrowed transport.
func (r *ForwardingRegistration) Close() error { return r.publisher.Close() }
