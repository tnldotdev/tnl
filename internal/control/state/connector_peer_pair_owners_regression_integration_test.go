package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func newConnectorPairPrerequisites(t *testing.T) (*Database, time.Time, PublishRunRequest, map[string]RelayLease) {
	t.Helper()
	return publishRunPrerequisitesWithRelayKeys(t, func(run string) []byte {
		seed := sha256.Sum256([]byte(run))
		return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	})
}

func newConnectorPairRunFixture(t *testing.T) publishRunFixture {
	t.Helper()
	d, now, request, leases := newConnectorPairPrerequisites(t)
	setup, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return publishRunFixture{d, now, request, setup, leases}
}

func nativeOwnerRows(t *testing.T, d *Database, ids []string) []byte {
	t.Helper()
	var saved []byte
	err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'pairs',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]') FROM control.connector_peer_pairs p WHERE id=ANY($1::text[])),
		'claims',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.pair_id,c.connection_slot),'[]') FROM control.connector_peer_pair_leg_claims c WHERE pair_id=ANY($1::text[])))::text`, ids).Scan(&saved)
	if err != nil {
		t.Fatal(err)
	}
	var facts []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(jsonb_build_object(
		'pair_id',p.id,'generation',p.delivery_generation,'expires_at',p.expires_at,'report_until',p.publisher_prepared_until,
		'claims',(SELECT COALESCE(jsonb_agg(jsonb_build_object('slot',c.connection_slot,'checked_at',c.checked_at,'confirmed_until',c.confirmed_until) ORDER BY c.connection_slot),'[]') FROM control.connector_peer_pair_leg_claims c WHERE c.pair_id=p.id)) ORDER BY p.id),'[]')::text FROM control.connector_peer_pairs p WHERE p.id=ANY($1::text[])`, ids).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	t.Logf("saved owner facts (no keys): %s", facts)
	return saved
}

// the same fixture runs for devices and workloads; only the authenticated source differs.
func assertNativeStateStableOwners(t *testing.T, d *Database, ctx context.Context, template ConnectorPeerPairRequest, key ed25519.PrivateKey, run ServiceRunState, now time.Time) {
	t.Helper()
	var owners [2]ConnectorPeerPair
	var requests [2]ConnectorPeerPairRequest
	ids := []string{}
	defer func() {
		if _, err := d.pool.Exec(t.Context(), `DELETE FROM control.connector_peer_pairs WHERE id=ANY($1::text[])`, ids); err != nil {
			t.Error(err)
		}
	}()
	for i, owner := range []string{"regression-owner-a", "regression-owner-b"} {
		r := template
		r.IdempotencyKey = owner
		signConnectorPairRequest(t, &r, key)
		pair, err := d.PrepareConnectorPeerPair(ctx, r, now)
		if err != nil {
			t.Fatal("valid independent owner", err)
		}
		owners[i], requests[i] = pair, r
		ids = append(ids, pair.ID)
		for slot := range pair.Relays {
			proof := testConnectorLegProof(t, pair, slot, now, key)
			if _, err := testClaimConnectorPeerPairLeg(t, d, t.Context(), pair.Relays[slot].RelayLease, netip.MustParseAddr("192.0.2.10"), proof, now); err != nil {
				t.Fatal("valid owner claim", err)
			}
		}
		// claims record elapsed checked time; the next operation starts afterward.
		at := now.Add(time.Second)
		delivery, err := d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, run.Token, at)
		if err != nil {
			t.Fatal("valid owner delivery", err)
		}
		if err := d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, run.Token, ConnectorPeerPairPrepared{DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: delivery.ExpiresAt}, at); err != nil {
			t.Fatal("valid owner report", err)
		}
	}
	if owners[0].ID == owners[1].ID || owners[0].Key == owners[1].Key {
		t.Fatal("independent fixture owners shared material")
	}
	for _, ownerKey := range []string{requests[1].IdempotencyKey, "fresh-unused-owner-c", ""} {
		before := nativeOwnerRows(t, d, ids)
		crossed := requests[1]
		crossed.IdempotencyKey, crossed.Action = ownerKey, "replace"
		crossed.PreviousPairID, crossed.PreviousGeneration = owners[0].ID, owners[0].DeliveryGeneration
		crossed.RequestedAt = now.Add(2 * time.Second)
		want := ErrServiceConflict
		if ownerKey == "" {
			want = ErrServiceAccess
		} else {
			signConnectorPairRequest(t, &crossed, key)
		}
		successor, err := d.PrepareConnectorPeerPair(ctx, crossed, crossed.RequestedAt)
		if successor.ID != "" {
			ids = append(ids, successor.ID)
		}
		after := nativeOwnerRows(t, d, ids)
		var aExists, bExists, adopted bool
		if scanErr := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.connector_peer_pairs WHERE id=$1),EXISTS(SELECT 1 FROM control.connector_peer_pairs WHERE id=$2),EXISTS(SELECT 1 FROM control.connector_peer_pairs WHERE id=$3 AND owner_key=$4)`, owners[0].ID, owners[1].ID, successor.ID, requests[0].IdempotencyKey).Scan(&aExists, &bExists, &adopted); scanErr != nil {
			t.Fatal(scanErr)
		}
		t.Logf("state subject=%s unused_key=%t before_sha256=%x after_sha256=%x a_retained=%t b_retained=%t adopted_a_owner=%t", template.Subject.Kind, ownerKey != requests[1].IdempotencyKey, sha256.Sum256(before), sha256.Sum256(after), aExists, bExists, adopted)
		if !errors.Is(err, want) || !bytes.Equal(before, after) || !aExists || !bExists || adopted {
			t.Fatalf("cross-owner replacement changed rows/claims/report/expiry or adopted owner: %v", err)
		}
	}
}
