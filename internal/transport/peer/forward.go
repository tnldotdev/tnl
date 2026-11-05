package peer

import (
	"context"
	"time"
)

// ForwardPackets forwards authenticated carrier frames without buffering or
// replaying them. a slot cut fences reads waiting for a destination and joins
// entered sends. an entered publisher send finishes within its original timeout
// and authority context: interrupting a retained stream can leave a partial frame.
// the bounded replay window belongs to this forwarding lifetime,
// not to any replacement carrier registration.
// forwarding into a slot requires a source from RegisterForwarding bound to it.
func ForwardPackets(ctx context.Context, source, destination Carrier) error {
	var replay replayWindow
	for {
		var destinationGeneration uint64
		destinationSlot, _ := destination.(*CarrierSlot)
		var frame []byte
		var generation uint64
		var err error
		sourceSlot, _ := source.(*CarrierSlot)
		if destinationSlot != nil {
			input, ok := source.(forwardingSource)
			if !ok {
				return ErrConfiguration
			}
			frame, destinationGeneration, err = input.receiveForward(ctx, destinationSlot)
			generation = destinationGeneration
		} else if sourceSlot != nil {
			frame, generation, err = sourceSlot.receiveGeneration(ctx)
		} else {
			frame, err = source.Receive(ctx)
		}
		if err != nil {
			return err
		}
		if !replay.acceptGeneration(frame, generation) {
			continue
		}
		call, cancel := context.WithTimeout(ctx, time.Second)
		var entered *installedCarrier
		if sourceSlot != nil {
			entered, err = sourceSlot.enter(call, generation)
			if entered == nil {
				cancel()
				if err != nil {
					return err
				}
				continue
			}
		}
		if destinationSlot != nil {
			err = destinationSlot.SendGeneration(call, frame, destinationGeneration)
		} else {
			err = destination.Send(call, frame)
		}
		cancel()
		if entered != nil {
			entered.work.Done()
		}
		if err != nil {
			return err
		}
	}
}

// forwarding sources stamp the destination generation at transport admission,
// before any shared input queue. a dequeue cannot assign old work a new carrier.
type forwardingSource interface {
	receiveForward(context.Context, *CarrierSlot) ([]byte, uint64, error)
}
