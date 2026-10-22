package publisher

import (
	"context"
	"errors"
	"fmt"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
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
			replacement, renewalErr := attemptCertificateTransaction(
				ctx, authority, route, state, true,
			)
			if renewalErr == nil {
				material = replacement
			}
			if renewalErr != nil {
				if errors.Is(renewalErr, controlclient.ErrStatusConflict) || errors.Is(renewalErr, controlclient.ErrUnauthenticated) {
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
