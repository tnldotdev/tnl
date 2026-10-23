package ingress

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// copyLivePrivateVisitor keeps the original stream and visitor ID. a denied
// recheck closes both ends; an unavailable control can never extend admission
// past two minutes since the last successful decision. the copy worker joins
// before the caller releases its ordinary stream capacity.
func (p *Connector) copyLivePrivateVisitor(ctx context.Context, visitor net.Conn, backend net.Conn,
	lease ingressv1.IngressLease, bound ingressv1.ConnectorSessionResult,
	claimed ingressv1.ServiceStreamResult, source netip.AddrPort, claimedAt time.Time) (retErr error) {
	ctx, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
	defer func() { finishForward(retErr) }()
	if !claimed.ValidUntil.After(time.Now()) {
		return ErrServiceAdmission
	}
	copyCtx, cancel := context.WithCancel(ctx)
	copyDone := make(chan error, 1)
	go func() {
		_, err := streamcopy.Copy(visitor, backend)
		copyDone <- err
	}()
	joined := false
	defer func() {
		cancel()
		_ = visitor.Close()
		_ = backend.Close()
		if !joined {
			<-copyDone
		}
	}()
	interval := p.config.RecheckInterval
	hardDeadline := privateMinTime(claimed.ValidUntil, claimedAt.Add(p.config.HardAuthorizationTTL))
	period := time.NewTimer(privateRecheckDelay(interval, p.config.RecheckTimeout, hardDeadline))
	defer period.Stop()
	hard := time.NewTimer(max(time.Until(hardDeadline), time.Nanosecond))
	defer hard.Stop()
	for {
		select {
		case err := <-copyDone:
			joined = true
			return err
		case <-copyCtx.Done():
			return copyCtx.Err()
		case <-hard.C:
			return ErrServiceAdmission
		case <-period.C:
			now := time.Now()
			if !now.Before(hardDeadline) {
				return ErrServiceAdmission
			}
			current, err := p.liveLease(now)
			if err != nil || !samePrivateLease(current, lease) {
				return ErrServiceAdmission
			}
			timeout := min(p.config.RecheckTimeout, time.Until(hardDeadline))
			checkCtx, finish := context.WithTimeout(copyCtx, timeout)
			result, err := p.config.Control.RecheckServiceVisitor(checkCtx, lease.IngressId,
				ingressv1.ServiceVisitorRecheck{
					IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
					ServiceId: claimed.ServiceId, ServiceRunId: claimed.ServiceRunId,
					RunNumber: claimed.RunNumber, ConnectorSessionId: bound.ConnectorSessionId,
					Subject: claimed.Subject, VisitorConnectionId: claimed.VisitorConnectionId,
					ObservedSourceIp: source.Addr().Unmap().String(),
				})
			finish()
			checkedAt := time.Now()
			if !checkedAt.Before(hardDeadline) {
				return ErrServiceAdmission
			}
			if err == nil {
				if !result.Allowed {
					return ErrServiceAdmission
				}
				if !result.ValidUntil.After(checkedAt) ||
					!result.RecheckAt.After(checkedAt.Add(-time.Second)) || result.RecheckAt.After(checkedAt.Add(interval+time.Second)) {
					err = ErrServiceAdmission
				} else {
					hardDeadline = privateMinTime(result.ValidUntil, checkedAt.Add(p.config.HardAuthorizationTTL))
					if !hard.Stop() {
						select {
						case <-hard.C:
						default:
						}
					}
					hard.Reset(max(time.Until(hardDeadline), time.Nanosecond))
				}
			}
			if err != nil && !time.Now().Before(hardDeadline) {
				return ErrServiceAdmission
			}
			next := interval
			if err == nil {
				next = max(time.Millisecond, min(interval, time.Until(result.RecheckAt)))
			}
			period.Reset(privateRecheckDelay(next, p.config.RecheckTimeout, hardDeadline))
		}
	}
}

// schedule against the actual admission deadline, including the initial claim
// and failed checks. reserve RPC time without extending the last authorization;
// a short remaining lease divides its budget between waiting and checking.
func privateRecheckDelay(interval, timeout time.Duration, deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	reserve := min(timeout, remaining/2)
	return max(time.Nanosecond, min(interval, remaining-reserve))
}

func privateMinTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
