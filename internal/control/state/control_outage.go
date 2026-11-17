package state

import (
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
)

// ConfigureControlOutageTolerance changes future confirmations, never an
// already-issued deadline. daemon composition configures this before serving.
func (d *Database) ConfigureControlOutageTolerance(tolerance time.Duration) error {
	if tolerance <= 0 {
		return errors.New("control outage tolerance must be positive")
	}
	d.controlOutageTolerance.Store(int64(tolerance))
	return nil
}

func (d *Database) servingTolerance() time.Duration {
	if duration := time.Duration(d.controlOutageTolerance.Load()); duration > 0 {
		return duration
	}
	return controloutage.DefaultTolerance
}
