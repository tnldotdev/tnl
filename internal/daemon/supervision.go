package daemon

import (
	"context"
	"fmt"

	"github.com/tnldotdev/tnl/internal/failure"
)

func runtimeCapacity(name string, value int64) (int, error) {
	converted := int(value)
	if value <= 0 || int64(converted) != value {
		return 0, fmt.Errorf("%s capacity is out of range", name)
	}
	return converted, nil
}

// start supervises a component for the process lifetime. only its first exit
// determines the result of Serve; shutdown joins every component, including
// those that exit after the result has been selected.
func (d *daemon) start(name string, run func() error) {
	d.components.Go(func() {
		err := run()
		if err != nil {
			reason, known := failure.ReasonOf(err)
			if !known {
				reason = failure.ServerComponentFailed
			}
			err = failure.Wrap(failure.Operation(name), reason, err)
		}
		select {
		case d.componentDone <- err:
		default:
		}
	})
}

// report the selected exit before shutdown loses the component name. caller
// cancellation stays normal control flow, not an operational fault.
func reportComponentFailure(ctx context.Context, err error) {
	if err == nil || ctx.Err() != nil {
		return
	}
	operation := failure.Operation("run configured role")
	if typed, ok := failure.Of(err); ok {
		operation = typed.Operation()
	}
	logOperationalError(ctx, operation, failure.ServerComponentFailed, err)
}

// background tracks work that can complete without ending the process, such
// as draining a relay after control updates its lease.
func (d *daemon) background(run func()) {
	d.components.Go(run)
}
