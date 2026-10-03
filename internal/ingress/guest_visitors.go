package ingress

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type guestVisitorControl interface {
	ReserveGuestVisitor(context.Context, string, ingressv1.GuestVisitorRequest) (ingressv1.GuestVisitorReservation, error)
	ReleaseGuestVisitor(context.Context, string, string) error
}

// OpenGuestVisitor reserves one service-wide guest slot and renews it until the visitor exits.
func (c *Controller) OpenGuestVisitor(
	ctx context.Context, publicURLID, visitorID string, closeVisitor func(),
) (func(), error) {
	client, ok := c.client.(guestVisitorControl)
	if !ok {
		return nil, errors.New("guest visitor admission is unavailable")
	}
	c.mu.RLock()
	lease := c.lease
	current := c.routingTableCurrent && !c.leaseLost
	c.mu.RUnlock()
	if !current || lease.IngressLeaseRevision <= 0 {
		return nil, ErrIngressLeaseLost
	}
	request := ingressv1.GuestVisitorRequest{
		IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		PublicUrlId: publicURLID, VisitorConnectionId: visitorID,
	}
	reserveCtx, stopReserve := context.WithTimeout(ctx, 5*time.Second)
	reservation, err := client.ReserveGuestVisitor(reserveCtx, lease.IngressId, request)
	stopReserve()
	if err != nil {
		return nil, err
	}
	renewCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		deadline := time.NewTimer(max(0, time.Until(reservation.ExpiresAt)))
		defer deadline.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-deadline.C:
				closeVisitor()
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(renewCtx, 5*time.Second)
				updated, err := client.ReserveGuestVisitor(checkCtx, lease.IngressId, request)
				stop()
				if err != nil {
					closeVisitor()
					return
				}
				if !deadline.Stop() {
					select {
					case <-deadline.C:
					default:
					}
				}
				deadline.Reset(max(0, time.Until(updated.ExpiresAt)))
			}
		}
	}()
	return func() {
		cancel()
		<-done
		closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = client.ReleaseGuestVisitor(closeCtx, lease.IngressId, visitorID)
	}, nil
}
