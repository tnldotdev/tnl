package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func runCertificateRenewals(
	ctx context.Context,
	config Config,
	authority publicRunAuthority,
	route *PublicURLServer,
	state *clientstate.CertificateCache,
	material clientstate.Material,
) error {
	// keep the cache lock across retries of one renewal, then release it before
	// waiting for the next renewal so another worktree can use the certificate.
	var renewalLock *clientstate.Lock
	defer func() { _ = renewalLock.Close() }()
	renewalTimer := time.NewTimer(max(time.Until(material.RenewAt), 0))
	renewal := renewalTimer.C
	defer renewalTimer.Stop()
	for {
		select {
		case <-route.admission.completed:
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			return nil
		case <-ctx.Done():
			_ = renewalLock.Close()
			return context.Cause(ctx)
		case <-renewal:
			if renewalLock == nil {
				lock, err := state.Lock(ctx)
				if err != nil {
					return err
				}
				renewalLock = lock
			}
			// waiting for another publish run's cache lock can cross expiry
			// before the session's expiration watcher cancels this worker.
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if !material.Certificate.Leaf.NotAfter.After(time.Now()) {
				return errCertificateExpired
			}
			replacement, renewalErr := attemptCertificateTransaction(
				ctx, authority, route, state, true,
			)
			if renewalErr == nil {
				material = replacement
			}
			if renewalErr != nil {
				if errors.Is(renewalErr, clientcontrol.ErrStatusConflict) || errors.Is(renewalErr, clientcontrol.ErrUnauthenticated) {
					return renewalErr
				}
				if ctx.Err() != nil {
					return context.Cause(ctx)
				}
				if !material.Certificate.Leaf.NotAfter.After(time.Now()) {
					return fmt.Errorf("publisher: renew expired certificate: %w", renewalErr)
				}
				logRenewalFailure(config.Logf, renewalErr)
				retryIn := certificateRenewalRetryDelay(renewalErr, material.Certificate.Leaf.NotAfter)
				expiresIn := time.Until(material.Certificate.Leaf.NotAfter)
				if retryIn >= expiresIn {
					renewal = nil
				} else {
					renewalTimer.Reset(retryIn)
				}
				continue
			}
			_ = renewalLock.Close()
			renewalLock = nil
			renewalTimer.Reset(max(time.Until(material.RenewAt), 0))
		}
	}
}
