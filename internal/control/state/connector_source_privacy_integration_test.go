package state

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationConnectorSourceEnvelopeIsolationRotationAndCleanup(t *testing.T) {
	f := newConnectorPairFixture(t)
	ctx := t.Context()
	pair := f.create(t)
	source := netip.MustParseAddr("192.0.2.10")
	for slot := range pair.Relays {
		if _, err := testClaimConnectorPeerPairLeg(t, f.d, f.visitor, pair.Relays[slot].RelayLease, source, testConnectorLegProof(t, pair, slot, f.now, f.key), f.now); err != nil {
			t.Fatal(err)
		}
	}
	q := controlstatedb.New(f.d.pool)
	claims, err := q.ReadConnectorPeerBindingClaims(ctx, controlstatedb.ReadConnectorPeerBindingClaimsParams{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration})
	if err != nil || len(claims) != 2 {
		t.Fatal("claim envelopes missing", err)
	}
	original := claims[0]
	if claims[0].SourceDigest != claims[1].SourceDigest || bytes.Equal(claims[0].SourceCiphertext, claims[1].SourceCiphertext) || bytes.Contains(original.SourceCiphertext, source.AsSlice()) {
		t.Fatal("claim equality or independent context encryption changed")
	}
	if got, err := f.d.openConnectorSource(ctx, q, pair.ServiceID, original); err != nil || got != source {
		t.Fatal("checked source could not be recovered", got, err)
	}
	for _, change := range []struct {
		name   string
		mutate func(*controlstatedb.ControlConnectorPeerPairLegClaim)
	}{
		{"ciphertext", func(c *controlstatedb.ControlConnectorPeerPairLegClaim) {
			c.SourceCiphertext = bytes.Clone(c.SourceCiphertext)
			c.SourceCiphertext[0] ^= 1
		}},
		{"digest", func(c *controlstatedb.ControlConnectorPeerPairLegClaim) {
			c.SourceDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}},
		{"pair", func(c *controlstatedb.ControlConnectorPeerPairLegClaim) { c.PairID += "other" }},
		{"generation", func(c *controlstatedb.ControlConnectorPeerPairLegClaim) { c.DeliveryGeneration++ }},
		{"slot", func(c *controlstatedb.ControlConnectorPeerPairLegClaim) { c.ConnectionSlot = 1 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			bad := original
			change.mutate(&bad)
			if _, err := f.d.openConnectorSource(ctx, q, pair.ServiceID, bad); err == nil {
				t.Fatal("envelope accepted altered content or context")
			}
		})
	}
	if _, err := f.d.openConnectorSource(ctx, q, "svc_abcdefghijkl0123456789", original); err == nil {
		t.Fatal("claim HMAC crossed its service")
	}
	rotated := rotateConnectorPairStorage(t, f.d, pair)
	q = controlstatedb.New(rotated.pool)
	claims, err = q.ReadConnectorPeerBindingClaims(ctx, controlstatedb.ReadConnectorPeerBindingClaimsParams{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration})
	if err != nil || len(claims) != 2 {
		t.Fatal(err)
	}
	for _, claim := range claims {
		if claim.SourceDigest != original.SourceDigest || claim.SourceStorageKeyID != rotated.storageKey.CurrentID() || bytes.Equal(claim.SourceCiphertext, original.SourceCiphertext) {
			t.Fatal("rotation changed equality or retained old ciphertext")
		}
		if got, err := rotated.openConnectorSource(ctx, q, pair.ServiceID, claim); err != nil || got != source {
			t.Fatal("current-key-only reopen lost checked source", got, err)
		}
	}
	if _, err := q.CleanupExpiredConnectorPeerPairs(ctx, controlstatedb.CleanupExpiredConnectorPeerPairsParams{Now: timestamptz(f.now.Add(10 * time.Minute)), BatchSize: 100}); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := rotated.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1`, pair.ID).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("expired pair retained reversible sources", retained, err)
	}
}
