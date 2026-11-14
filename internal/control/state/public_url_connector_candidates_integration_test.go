package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func installPublicURLConnectorPair(t *testing.T, public publishRunFixture, native connectorPairFixture, pair ConnectorPeerPair) time.Time {
	t.Helper()
	at := native.now.Add(time.Second)
	for slot := range 2 {
		proof := testConnectorLegProof(t, pair, slot, at, native.key)
		if _, err := testClaimConnectorPeerPairLeg(t, native.d, t.Context(), pair.Relays[slot].RelayLease, netip.MustParseAddr("192.0.2.9"), proof, at); err != nil {
			t.Fatal("claim public URL installation leg", err)
		}
	}
	at = at.Add(time.Second)
	delivery, err := native.d.DeliverPublicURLConnectorPeerPair(t.Context(), public.authentication(), pair.ID, pair.DeliveryGeneration, at)
	if err != nil {
		t.Fatal("prepare public URL installation", err)
	}
	err = native.d.ConfirmPublicURLConnectorPeerPairPrepared(t.Context(), public.authentication(), pair.ID, ConnectorPeerPairPrepared{
		DeliveryID: delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		BindingExpiresAt: delivery.ExpiresAt, Phase: "installed",
	}, at)
	if err != nil {
		t.Fatal("install public URL binding", err)
	}
	return at.Add(time.Second)
}

func TestIntegrationPublicURLConnectorCandidatesKeepExactFamilyAndBoundedPages(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	service := connectorPairFixtureFromRun(t, public)
	servicePair := service.create(t)
	auth := public.authentication()
	for name, edit := range map[string]func(*PublishRunAuthentication){
		"empty token":   func(a *PublishRunAuthentication) { a.PublishRunToken = "" },
		"service token": func(a *PublishRunAuthentication) { a.PublishRunToken = credentials.PublishRunToken(service.run.Token) },
		"run number":    func(a *PublishRunAuthentication) { a.PublishRunNumber++ },
		"run id":        func(a *PublishRunAuthentication) { a.PublishRunID = "pr_1234567890123456789012" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := auth
			edit(&changed)
			page, err := native.d.ListPublicURLConnectorPeerPairs(t.Context(), changed, "", native.now)
			if err == nil || len(page.Items) != 0 || page.NextAfter != "" {
				t.Fatal("unrelated publisher discovered public URL owners")
			}
		})
	}
	if _, err := native.d.ListPublicURLConnectorPeerPairs(t.Context(), auth, "invalid", native.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("invalid public URL cursor accepted", err)
	}
	page, err := native.d.ListPublicURLConnectorPeerPairs(t.Context(), auth, "", native.now)
	if err != nil || len(page.Items) != 1 || page.Items[0].PairID != pair.ID || page.Items[0].OwnerAuthority != nil {
		t.Fatal("public URL candidates mixed service owners or authorized uninstalled delivery", err)
	}
	servicePage, err := native.d.ListConnectorPeerPairs(t.Context(), servicePair.ServiceID, servicePair.ServiceRunID, "", service.run.Token, native.now)
	if err != nil || len(servicePage.Items) != 1 || servicePage.Items[0].PairID != servicePair.ID {
		t.Fatal("service candidates included public URL owners", err)
	}
	assertConnectorPairCandidateInventory(t, native.d, pair, native.now, func(after string) (ConnectorPeerPairCandidates, error) {
		return native.d.ListPublicURLConnectorPeerPairs(t.Context(), auth, after, native.now)
	})
}

func TestIntegrationPublicURLConnectorCandidatesReconcileWithoutServingReadiness(t *testing.T) {
	for _, mutation := range []string{"starting", "certificate", "retired key", "revoked grant"} {
		t.Run(mutation, func(t *testing.T) {
			public, native, publisher := publicURLConnectorPairFixture(t)
			pair := native.create(t)
			at := installPublicURLConnectorPair(t, public, native, pair)
			query, id := `UPDATE control.publish_runs SET state='starting',ready_at=NULL WHERE id=$1`, pair.PublishRunID
			switch mutation {
			case "certificate":
				query = `UPDATE control.publish_runs SET certificate_not_after=created_at+interval '1 microsecond' WHERE id=$1`
			case "retired key":
				query, id = `UPDATE control.publisher_identity_keys SET retired_at=created_at WHERE id=$1`, publisher.KeyID
			case "revoked grant":
				query, id = `UPDATE control.publisher_grants SET revoked_at=created_at WHERE id=$1`, publisher.GrantID
			}
			if _, err := native.d.pool.Exec(t.Context(), query, id); err != nil {
				t.Fatal(err)
			}
			before := connectorPairSavedAuthority(t, native.d, pair.ID)
			page, err := native.d.ListPublicURLConnectorPeerPairs(t.Context(), public.authentication(), "", at)
			if mutation == "retired key" || mutation == "revoked grant" {
				if err == nil || len(page.Items) != 0 {
					t.Fatal("revoked publisher retained hint access")
				}
			} else if err != nil || len(page.Items) != 1 || page.Items[0].PairID != pair.ID || page.Items[0].OwnerAuthority != nil {
				t.Fatal("serving readiness replaced hint-only reconciliation", err)
			}
			if !bytes.Equal(before, connectorPairSavedAuthority(t, native.d, pair.ID)) {
				t.Fatal("hint listing changed owner, installation, claim, or proof")
			}
		})
	}
}

func TestIntegrationPublicURLConnectorCandidateOwnerSurvivesRelayRecoveryNotSourceRevocation(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	at := installPublicURLConnectorPair(t, public, native, pair)
	request := connectorRebindRequest(t, native, pair, "prepare", at)
	rebind, err := native.d.RebindPublicURLConnectorPeerPair(native.visitor, pair.PublicURLID, pair.ID, request, at)
	if err != nil || rebind.Pending == nil {
		t.Fatal("prepare pending candidate", err)
	}
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state='starting' WHERE id=$1`, pair.PublishRunID); err != nil {
		t.Fatal(err)
	}
	for slot, assignment := range public.setup.PublisherConnections {
		claim := PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: assignment.ConnectionAssignmentIdentity,
			RelayLeaseIdentity: public.leases[assignment.RelayServiceID].RelayLeaseIdentity, ClaimID: fmt.Sprintf("claim-%d", slot)}
		if _, err := native.d.DisconnectPublisherConnection(t.Context(), claim, at, true); err != nil {
			t.Fatal("disconnect public URL fixture publisher", err)
		}
	}
	before := connectorPairSavedAuthority(t, native.d, pair.ID)
	page, err := native.d.ListPublicURLConnectorPeerPairs(t.Context(), public.authentication(), "", at)
	if err != nil || len(page.Items) != 1 || page.Items[0].DeliveryGeneration != rebind.Pending.DeliveryGeneration ||
		page.Items[0].OwnerAuthority == nil || !page.Items[0].OwnerAuthority.ExpiresAt.Equal(pair.ExpiresAt) {
		t.Fatal("relay loss hid the retained owner's independent authority", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, native.d, pair.ID)) {
		t.Fatal("candidate observation extended pending or installation authority")
	}
	if err := native.d.RevokeVisitorDevice(t.Context(), pair.Subject.IdentityID, pair.Subject.DeviceID, at); err != nil {
		t.Fatal(err)
	}
	page, err = native.d.ListPublicURLConnectorPeerPairs(t.Context(), public.authentication(), "", at)
	if err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority != nil {
		t.Fatal("revoked original source retained an owner observation", err)
	}
}

func TestIntegrationPublicURLConnectorCandidateObservationExpiresAfterPairWait(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	at := installPublicURLConnectorPair(t, public, native, pair)
	principal := native.visitor.Value(controlPrincipalKey{}).(ControlPrincipal)
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gate, err := native.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(t.Context(), `SELECT id FROM control.connector_peer_pairs WHERE id=$1 FOR UPDATE`, pair.ID); err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, native.d, pair.ID)
	entered := make(chan time.Time, 1)
	var page ConnectorPeerPairCandidates
	done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
		entered <- time.Now()
		var err error
		page, err = native.d.ListPublicURLConnectorPeerPairs(ctx, public.authentication(), "", at)
		return err
	})
	defer join()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	waitForPostgresBlock(t, ctx, native.d, int32(gate.Conn().PgConn().PID()), done)
	started := awaitIntegrationResult(t, ctx, entered)
	timer := time.NewTimer(time.Until(started.Add(time.Second + 10*time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority != nil {
		t.Fatal("listing borrowed an expired original parent's authority after waiting", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, native.d, pair.ID)) {
		t.Fatal("expired public URL owner observation changed durable state")
	}
}
