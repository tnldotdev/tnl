package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (b *connectorConnectionBackend) lockWorkloadSession(ctx context.Context) (func(), error) {
	b.mu.Lock()
	if b.sessionGate == nil {
		b.sessionGate = make(chan struct{}, 1)
	}
	gate := b.sessionGate
	b.mu.Unlock()
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *connectorConnectionBackend) publishWorkloadAssertion(client *workload.Client, assertion string, session authorityv1.WorkloadSession) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.workload != client {
		return connectorruntime.ErrExpired
	}
	b.deadline = workload.SessionDeadline(session)
	if session.AssertionExpiresAt != nil {
		b.rememberAssertion(assertion, *session.AssertionExpiresAt, session)
	} else {
		b.verification = nil
	}
	b.publishLocked()
	return nil
}

// startWorkloadRefreshLocked belongs to the process owner, not a request. the
// worker only refreshes this exact live session; it never creates a replacement.
func (b *connectorConnectionBackend) startWorkloadRefreshLocked() {
	if b.closed || b.workload == nil || b.refreshAssertion == nil || b.lifetime == nil {
		return
	}
	client, acquire, lifetime := b.workload, b.refreshAssertion, b.lifetime
	b.workers.Go(func() { b.refreshWorkloadIdentity(lifetime, client, acquire) })
}

func identityRefreshDelay(now, expiry time.Time, retry bool) time.Duration {
	remaining := expiry.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if retry {
		return min(5*time.Second, max(50*time.Millisecond, remaining/4))
	}
	return remaining - min(2*time.Minute, remaining/3)
}

func (b *connectorConnectionBackend) refreshWorkloadIdentity(ctx context.Context, client *workload.Client, acquire func(context.Context) (string, error)) {
	var proofExpiry, refreshAt time.Time
	for {
		b.mu.Lock()
		current := !b.closed && b.workload == client
		b.mu.Unlock()
		if !current || ctx.Err() != nil {
			return
		}
		session, err := client.Session()
		if err != nil {
			return
		}
		expiry := minTime(session.LeaseExpiresAt, workload.SessionDeadline(session))
		if !expiry.After(time.Now()) {
			return
		}
		if !session.IdentityExpiresAt.Equal(proofExpiry) {
			proofExpiry = session.IdentityExpiresAt
			refreshAt = time.Now().Add(identityRefreshDelay(time.Now(), proofExpiry, false))
		}
		// permission renewal has its own loop. proof refresh is scheduled from the
		// verified identity horizon, but never waits past its last accepted lease.
		timer := time.NewTimer(time.Until(minTime(refreshAt, expiry)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		latest, err := client.Session()
		if err != nil {
			return
		}
		if latest.IdentityExpiresAt.After(proofExpiry) || time.Now().Before(refreshAt) {
			continue
		}
		// a shortened lease or an unavailable authority cannot give acquisition
		// extra time. a later request must explicitly establish fresh authority.
		until := minTime(time.Now().Add(10*time.Second), minTime(latest.LeaseExpiresAt, workload.SessionDeadline(latest)))
		call, cancel := context.WithDeadline(ctx, until)
		err = b.refreshWorkloadProof(call, client, acquire)
		cancel()
		if ctx.Err() != nil {
			return
		}
		next, readErr := client.Session()
		if readErr != nil {
			return
		}
		if err != nil || !next.IdentityExpiresAt.After(latest.IdentityExpiresAt) {
			refreshAt = time.Now().Add(identityRefreshDelay(time.Now(), next.IdentityExpiresAt, true))
		}
	}
}

func (b *connectorConnectionBackend) refreshWorkloadProof(ctx context.Context, client *workload.Client, acquire func(context.Context) (string, error)) error {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	assertion, err := acquire(ctx)
	if err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	unlock, err := b.lockWorkloadSession(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	b.mu.Lock()
	current := !b.closed && b.workload == client
	digest := sha256.Sum256([]byte(assertion))
	_, known := b.assertions[hex.EncodeToString(digest[:])]
	b.mu.Unlock()
	if !current {
		return connectorruntime.ErrExpired
	}
	session, err := client.Session()
	if err != nil {
		return err
	}
	if !session.LeaseExpiresAt.After(time.Now()) || !workload.SessionDeadline(session).After(time.Now()) {
		return connectorruntime.ErrExpired
	}
	if known {
		return nil
	}
	next, err := client.Attach(ctx, assertion)
	if err != nil {
		return err
	}
	return b.publishWorkloadAssertion(client, assertion, next)
}
