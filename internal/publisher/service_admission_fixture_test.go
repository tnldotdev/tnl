package publisher

import (
	"context"
	"time"
)

// NativeAdmissionFixture supplies only the consumer's local decision in protocol
// and target tests. it does not construct a production admission or prove a pair.
// service's real connector owner tests cover signed entry, capacity and joined life.
type NativeAdmissionFixture struct {
	Check func(context.Context) (ServiceVisitorDecision, error)
}

func (a NativeAdmissionFixture) CheckUse(ctx context.Context) (time.Time, error) {
	decision, err := a.Check(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return time.Time{}, ErrEndpoint
	}
	return decision.ValidUntil, nil
}
func (NativeAdmissionFixture) SetupDeadline() time.Time { return time.Now().Add(10 * time.Second) }
func (NativeAdmissionFixture) FinishSetup() error       { return nil }
func (NativeAdmissionFixture) Stop()                    {}
