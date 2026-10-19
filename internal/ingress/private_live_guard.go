package ingress

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

// copyLivePrivateVisitor keeps the original stream and visitor ID. a denied
// recheck closes both ends; an unavailable control can never extend admission
// past two minutes since the last successful decision. the copy worker joins
// before the caller releases its ordinary stream capacity.
func (p *PrivateConnector) copyLivePrivateVisitor(ctx context.Context, visitor muxsession.Stream, backend net.Conn,
	lease ingressv1.IngressLease, bound ingressv1.PrivateConnectorSessionResult,
	claimed ingressv1.PrivateServiceStreamResult, source netip.AddrPort, claimedAt time.Time) error {
	if !claimed.ValidUntil.After(time.Now()) {
		return ErrPrivateAdmission
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
			return ErrPrivateAdmission
		case <-period.C:
			now := time.Now()
			if !now.Before(hardDeadline) {
				return ErrPrivateAdmission
			}
			current, err := p.liveLease(now)
			if err != nil || !samePrivateLease(current, lease) {
				return ErrPrivateAdmission
			}
			timeout := min(p.config.RecheckTimeout, time.Until(hardDeadline))
			checkCtx, finish := context.WithTimeout(copyCtx, timeout)
			result, err := p.config.Control.RecheckPrivateServiceVisitor(checkCtx, lease.IngressId,
				ingressv1.PrivateServiceVisitorRecheck{
					IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
					PrivateServiceId: claimed.PrivateServiceId, PrivateRunId: claimed.PrivateRunId,
					RunNumber: claimed.RunNumber, ConnectorSessionId: bound.ConnectorSessionId,
					IdentityId: claimed.IdentityId, VisitorConnectionId: claimed.VisitorConnectionId,
					ObservedSourceIp: source.Addr().Unmap().String(),
				})
			finish()
			checkedAt := time.Now()
			if !checkedAt.Before(hardDeadline) {
				return ErrPrivateAdmission
			}
			if err == nil {
				if !result.Allowed {
					return ErrPrivateAdmission
				}
				if !result.ValidUntil.After(checkedAt) ||
					!result.RecheckAt.After(checkedAt.Add(-time.Second)) || result.RecheckAt.After(checkedAt.Add(interval+time.Second)) {
					err = ErrPrivateAdmission
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
				return ErrPrivateAdmission
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
