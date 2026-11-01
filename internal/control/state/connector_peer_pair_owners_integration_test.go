package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func assertConnectorPairOwnerIsolation(t *testing.T, d *Database, ctx context.Context, request ConnectorPeerPairRequest, first ConnectorPeerPair, key ed25519.PrivateKey, now time.Time) {
	t.Helper()
	sign := func(r *ConnectorPeerPairRequest) {
		t.Helper()
		message, err := r.proof().Message()
		if err != nil {
			t.Fatal(err)
		}
		r.Signature = ed25519.Sign(key, message)
	}
	secondRequest := request
	secondRequest.IdempotencyKey = "independent-owner"
	sign(&secondRequest)
	second, err := d.PrepareConnectorPeerPair(ctx, secondRequest, now)
	if err != nil {
		t.Fatal("new connector owner with the same enrolled subject", err)
	}
	inserted := []string{second.ID}
	defer func() {
		if _, err := d.pool.Exec(ctx, `DELETE FROM control.connector_peer_pairs WHERE id=ANY($1::text[])`, inserted); err != nil {
			t.Error(err)
		}
	}()
	if second.ID == first.ID || second.Key == first.Key || second.DeliveryID == first.DeliveryID || second.DeliveryGeneration == first.DeliveryGeneration || !second.PublisherPreparedUntil.IsZero() {
		t.Fatal("new owner inherited delivery or publisher preparation")
	}
	var claims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1`, second.ID).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("new owner inherited relay claims", err)
	}
	var retries sync.WaitGroup
	for _, owner := range []struct {
		request ConnectorPeerPairRequest
		pair    ConnectorPeerPair
	}{{request, first}, {secondRequest, second}} {
		for range 3 {
			retries.Go(func() {
				pair, err := d.PrepareConnectorPeerPair(ctx, owner.request, now)
				if err != nil || pair.ID != owner.pair.ID || pair.Key != owner.pair.Key || pair.DeliveryID != owner.pair.DeliveryID || !pair.ExpiresAt.Equal(owner.pair.ExpiresAt) {
					t.Errorf("owner retry changed delivery or authority: %v", err)
				}
			})
		}
	}
	retries.Wait()
	// a fresh, correctly signed renewal still needs the exact owner pair and key.
	crossed := secondRequest
	crossed.Action, crossed.PreviousPairID, crossed.PreviousGeneration = "renew", first.ID, first.DeliveryGeneration
	crossed.RequestedAt = now.Add(time.Microsecond)
	sign(&crossed)
	if _, err := d.RenewConnectorPeerPair(ctx, crossed, crossed.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another owner's request key renewed the first pair", err)
	}
	crossed.Action = "replace"
	sign(&crossed)
	if _, err := d.PrepareConnectorPeerPair(ctx, crossed, crossed.RequestedAt); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("another owner's request key replaced the first pair", err)
	}
	for index := range maxConnectorPeerPairOwners - 2 {
		next := request
		next.IdempotencyKey = fmt.Sprintf("bounded-owner-%d", index)
		sign(&next)
		pair, err := d.PrepareConnectorPeerPair(ctx, next, now)
		if err != nil {
			t.Fatal("prepare bounded owner", err)
		}
		inserted = append(inserted, pair.ID)
	}
	full := request
	full.IdempotencyKey = "over-owner-budget"
	sign(&full)
	if _, err := d.PrepareConnectorPeerPair(ctx, full, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("unbounded connector owner inventory", err)
	}
	if retry, err := d.PrepareConnectorPeerPair(ctx, request, now); err != nil || retry.ID != first.ID {
		t.Fatal("full inventory blocked an exact retry", err)
	}
	// expiry does not free a row while its signed creation can still be replayed.
	if _, err := d.pool.Exec(ctx, `UPDATE control.connector_peer_pairs SET created_at=$2,last_authorized_at=$2,expires_at=$3 WHERE id=$1`, second.ID, now.Add(-time.Minute), now.Add(-time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareConnectorPeerPair(ctx, full, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("expiry discarded the retained owner budget", err)
	}
	replace := secondRequest
	replace.Action = "replace"
	replace.PreviousPairID, replace.PreviousGeneration = second.ID, second.DeliveryGeneration
	replace.RequestedAt = now.Add(time.Microsecond)
	sign(&replace)
	replaced, err := d.PrepareConnectorPeerPair(ctx, replace, replace.RequestedAt)
	if err != nil {
		t.Fatal("full inventory blocked exact replacement", err)
	}
	inserted[0] = replaced.ID
	if retry, err := d.PrepareConnectorPeerPair(ctx, replace, replace.RequestedAt); err != nil || retry.ID != replaced.ID {
		t.Fatal("replacement retry consumed another owner slot", err)
	}
	if _, err := d.PrepareConnectorPeerPair(ctx, secondRequest, replace.RequestedAt); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("replacement lost its original owner replay fence", err)
	}
	// a fully expired row awaiting cleanup no longer holds a slot. replacement
	// must reacquire capacity rather than increase the live inventory beyond 64.
	if _, err := d.pool.Exec(ctx, `UPDATE control.connector_peer_pairs
		SET created_at=$2,last_authorized_at=$2,expires_at=$3,last_request_at=$4,replay_fence_until=$3 WHERE id=$1`,
		replaced.ID, now.Add(-time.Minute), now.Add(-time.Microsecond), now.Add(-5*time.Minute-time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	newOwner, err := d.PrepareConnectorPeerPair(ctx, full, now)
	if err != nil {
		t.Fatal("fully expired owner retained capacity", err)
	}
	inserted = append(inserted, newOwner.ID)
	replace.PreviousPairID, replace.PreviousGeneration = replaced.ID, replaced.DeliveryGeneration
	sign(&replace)
	if _, err := d.PrepareConnectorPeerPair(ctx, replace, replace.RequestedAt); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("expired replacement exceeded owner capacity", err)
	}
	var retained bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.connector_peer_pairs WHERE id=$1)`, replaced.ID).Scan(&retained); err != nil || !retained {
		t.Fatal("rejected replacement deleted its predecessor", err)
	}
}
