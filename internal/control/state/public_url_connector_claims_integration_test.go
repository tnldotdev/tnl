package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationPublicURLConnectorClaimsBindExactPublicationAndSource(t *testing.T) {
	_, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	source := netip.MustParseAddr("192.0.2.9")
	for slot := range 2 {
		proof := testConnectorLegProof(t, pair, slot, native.now, native.key)
		lease := pair.Relays[slot].RelayLease
		claim, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, native.now)
		if err != nil || claim.PairID != pair.ID || claim.DeliveryGeneration != pair.DeliveryGeneration ||
			claim.DeliveryID != pair.DeliveryID || claim.Key != pair.Key || claim.SourceIP != source ||
			claim.ExpiresAt.After(pair.ExpiresAt) || !claim.ExpiresAt.After(native.now) {
			t.Fatal("public URL relay claim changed exact delivery authority", err)
		}
		if replay, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, native.now); !errors.Is(err, ErrServiceAccess) || replay.Key != "" {
			t.Fatal("public URL relay claim replay released a key", err)
		}
	}
	next := native.now.Add(time.Second)
	proof := testConnectorLegProof(t, pair, 0, next, native.key)
	lease := pair.Relays[0].RelayLease
	if got, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, netip.MustParseAddr("192.0.2.10"), proof, next); !errors.Is(err, ErrConnectorPeerBindingStale) || got.Key != "" {
		t.Fatal("changed observed source reused an active public URL binding", err)
	}
	changed := pair
	changed.PublishRunNumber++
	proof = testConnectorLegProof(t, changed, 0, next, native.key)
	if got, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, next); !errors.Is(err, ErrServiceAccess) || got.Key != "" {
		t.Fatal("another publish run number released an existing pair key", err)
	}
	if err := native.d.RevokeVisitorDevice(t.Context(), native.request.Subject.IdentityID, native.request.Subject.DeviceID, next); err != nil {
		t.Fatal(err)
	}
	proof = testConnectorLegProof(t, pair, 0, next, native.key)
	if got, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, next); !errors.Is(err, ErrServiceAccess) || got.Key != "" {
		t.Fatal("revoked original device renewed public URL relay authority", err)
	}
	claims, err := controlstatedb.New(native.d.pool).ReadConnectorPeerBindingClaims(t.Context(), controlstatedb.ReadConnectorPeerBindingClaimsParams{
		PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration})
	if err != nil || len(claims) != 2 {
		t.Fatal("rejected claims changed the retained relay legs", err)
	}
	for _, claim := range claims {
		if !claim.RequestedAt.Time.Equal(native.now) || claim.SourceIp != source {
			t.Fatal("rejected authority changed a relay claim")
		}
	}
}

func TestIntegrationPublicURLConnectorClaimsRetainCurrentIPPolicyAndExpiry(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	url, err := native.d.GetPublicURL(t.Context(), public.request.ActingIdentityID, pair.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.d.ReplaceVisitorAccess(t.Context(), url.ID, public.request.ActingIdentityID, VisitorAccessRestricted,
		[]string{"192.0.2.9/32"}, url.MutationRevision, native.now); err != nil {
		t.Fatal(err)
	}
	expires := native.now.Add(5 * time.Second)
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.visitor_ip_grants SET expires_at=$2 WHERE public_url_id=$1 AND revoked_at IS NULL`, url.ID, expires); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.9")
	lease := pair.Relays[0].RelayLease
	proof := testConnectorLegProof(t, pair, 0, native.now, native.key)
	if denied, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, netip.MustParseAddr("192.0.2.10"), proof, native.now); !errors.Is(err, ErrServiceAccess) || denied.Key != "" {
		t.Fatal("public URL relay claim ignored the current IP filter", err)
	}
	claim, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, native.now)
	if err != nil || claim.Key != pair.Key || !claim.ExpiresAt.Equal(expires) {
		t.Fatal("public URL relay authority outlived its matching IP grant", err)
	}
	next := expires.Add(time.Microsecond)
	proof = testConnectorLegProof(t, pair, 0, next, native.key)
	if denied, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), lease, source, proof, next); !errors.Is(err, ErrServiceAccess) || denied.Key != "" {
		t.Fatal("expired IP permission renewed public URL relay authority", err)
	}
}

func TestIntegrationPublicURLConnectorPublisherDeliveryRequiresExactClaimsAndRunToken(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	auth := public.authentication()
	at := native.now.Add(time.Second)
	if got, err := native.d.DeliverPublicURLConnectorPeerPair(t.Context(), auth, pair.ID, pair.DeliveryGeneration, at); !errors.Is(err, ErrServiceAccess) || got.Key != "" || got.SessionKey != "" {
		t.Fatal("publisher delivery did not require exact relay claims", err)
	}
	source := netip.MustParseAddr("192.0.2.9")
	for slot := range 2 {
		proof := testConnectorLegProof(t, pair, slot, native.now, native.key)
		if _, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), pair.Relays[slot].RelayLease, source, proof, native.now); err != nil {
			t.Fatal(err)
		}
	}
	delivery, err := native.d.DeliverPublicURLConnectorPeerPair(t.Context(), auth, pair.ID, pair.DeliveryGeneration, at)
	if err != nil || delivery.PublicURLID != pair.PublicURLID || delivery.PublishRunID != pair.PublishRunID ||
		delivery.PublishRunNumber != pair.PublishRunNumber || delivery.ServiceID != "" || delivery.ServiceRunID != "" || delivery.RunNumber != 0 ||
		delivery.Key != pair.Key || delivery.SessionKey != pair.SessionKey || delivery.SourceIP != source || delivery.Subject != native.request.Subject {
		t.Fatal("publisher delivery crossed its typed public URL binding", err)
	}
	wrong := auth
	wrong.PublishRunNumber++
	if got, err := native.d.DeliverPublicURLConnectorPeerPair(t.Context(), wrong, pair.ID, pair.DeliveryGeneration, at); !errors.Is(err, ErrPublishRunStale) || got.Key != "" || got.SessionKey != "" {
		t.Fatal("another publish run number reused publisher credentials", err)
	}
	service := connectorPairFixtureFromRun(t, public)
	if got, err := native.d.DeliverConnectorPeerPair(t.Context(), service.request.ServiceID, service.run.RunID, pair.ID,
		pair.DeliveryGeneration, service.run.Token, at); !errors.Is(err, ErrServiceAccess) || got.Key != "" || got.SessionKey != "" {
		t.Fatal("a service run token delivered a public URL pair", err)
	}
	report := ConnectorPeerPairPrepared{DeliveryID: delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		BindingExpiresAt: delivery.ExpiresAt, Phase: "installed", OperationID: delivery.OperationID, BindingChallenge: delivery.BindingChallenge}
	if err := native.d.ConfirmPublicURLConnectorPeerPairPrepared(t.Context(), auth, pair.ID, report, at); err != nil {
		t.Fatal("exact public URL installation was rejected", err)
	}
	var retained bool
	err = native.d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.connector_peer_audit_bindings
		WHERE pair_id=$1 AND public_url_id=$2 AND publish_run_id=$3 AND publish_run_number=$4
		AND service_id='' AND service_run_id='' AND run_number=0 AND source_ip=$5)`,
		pair.ID, pair.PublicURLID, pair.PublishRunID, pair.PublishRunNumber, source).Scan(&retained)
	if err != nil || !retained {
		t.Fatal("publisher installation did not retain its typed audit scope", err)
	}
}

func TestIntegrationPublicURLConnectorRebindReusesOwnerAndPublication(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	at := native.now.Add(time.Second)
	inspect := connectorRebindRequest(t, native, pair, "inspect", at)
	state, err := native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, inspect, at)
	if err != nil || state.Active == nil || state.Active.PublicURLID != pair.PublicURLID || state.Pending != nil {
		t.Fatal("public URL inspection lost its typed owner", err)
	}
	other, err := native.d.CreatePreview(t.Context(), public.request.TeamID, public.request.ActingIdentityID, "different-rebind-preview", native.now)
	if err != nil {
		t.Fatal(err)
	}
	changed := inspect
	device := native.request.Source.(DeviceTokenSource)
	device.PreviewID = other.ID
	changed.Source = device
	if got, err := native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, changed, at); !errors.Is(err, ErrServiceAccess) || got.Active != nil {
		t.Fatal("rebind inspection changed the original preview selection", err)
	}
	prepare := connectorRebindRequest(t, native, pair, "prepare", at)
	state, err = native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, prepare, at)
	if err != nil || state.Pending == nil {
		t.Fatal("public URL binding preparation failed", err)
	}
	pending := *state.Pending
	abort := connectorRebindRequest(t, native, pending, "abort", at.Add(time.Second))
	abort.Proof.OperationID = pending.OperationID
	abort = signConnectorRebind(t, native, abort.Proof)
	state, err = native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, abort, abort.Proof.RequestedAt)
	if err != nil || state.Pending != nil || state.Active == nil || state.Active.SessionKey != pair.SessionKey {
		t.Fatal("public URL abort replaced or revived an owner", err)
	}
	prepare = connectorRebindRequest(t, native, pair, "prepare", at.Add(2*time.Second))
	prepare.Proof.ExpectedGeneration = state.HighWaterGeneration
	prepare = signConnectorRebind(t, native, prepare.Proof)
	state, err = native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, prepare, prepare.Proof.RequestedAt)
	if err != nil || state.Pending == nil || state.Pending.DeliveryGeneration <= pending.DeliveryGeneration {
		t.Fatal("public URL retry reused an aborted generation", err)
	}
	pending = *state.Pending
	connectorRebindClaimBoth(t, native, pending, netip.MustParseAddr("192.0.2.10"), at.Add(3*time.Second))
	for index, phase := range []string{"installed", "proved"} {
		report := ConnectorPeerPairPrepared{Phase: phase, OperationID: pending.OperationID, BindingChallenge: pending.BindingChallenge,
			DeliveryID: pending.DeliveryID, DeliveryGeneration: pending.DeliveryGeneration, BindingExpiresAt: pending.ExpiresAt}
		if phase == "proved" {
			report.PathProofs = connectorRebindProofs(t, pending, 1)
		}
		if err := native.d.ConfirmPublicURLConnectorPeerPairPrepared(t.Context(), public.authentication(), pair.ID, report, at.Add(time.Duration(4+index)*time.Second)); err != nil {
			t.Fatal("public URL publisher rejected its exact pending binding", phase, err)
		}
	}
	activate := connectorRebindRequest(t, native, pending, "inspect", at.Add(6*time.Second))
	activate.Proof.Phase, activate.Proof.OperationID, activate.Proof.BindingChallenge = "activate", pending.OperationID, pending.BindingChallenge
	activate.Proof.PathProofs = connectorRebindProofs(t, pending, 0)
	activate = signConnectorRebind(t, native, activate.Proof)
	state, err = native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, activate, activate.Proof.RequestedAt)
	if err != nil || state.Active == nil || state.Pending != nil || state.Active.SessionKey != pair.SessionKey ||
		state.Active.PublicURLID != pair.PublicURLID || state.Active.PublishRunID != pair.PublishRunID || state.Active.PublishRunNumber != pair.PublishRunNumber ||
		state.Active.ServiceID != "" || state.Active.DeliveryGeneration != pending.DeliveryGeneration || state.Active.Key != pending.Key {
		t.Fatal("public URL activation changed publication or inner-session ownership", err)
	}
}
