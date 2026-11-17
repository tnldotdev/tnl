package state

import "github.com/tnldotdev/tnl/internal/policy/publisherenrollment"

// ConfigurePublisherEnrollmentLimits applies admission ceilings before serving.
// already-issued keys retain their captured capacity and deadline.
func (d *Database) ConfigurePublisherEnrollmentLimits(limits publisherenrollment.Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	d.publisherEnrollmentLimits.Store(&limits)
	return nil
}

func (d *Database) enrollmentLimits() publisherenrollment.Limits {
	if selected := d.publisherEnrollmentLimits.Load(); selected != nil {
		return *selected
	}
	return publisherenrollment.Default()
}
