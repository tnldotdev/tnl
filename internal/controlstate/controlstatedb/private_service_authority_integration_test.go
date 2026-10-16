package controlstatedb_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationPrivateServiceAuthority(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "private_authority")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	now := time.Now().UTC()
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := credentials.ParseLoginToken(login)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := d.CreateBuiltinControlSession(ctx, "example.test", verifier.SourceRevision(), time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	identityID := owner.Identity.Identity.ID
	teamID := owner.Identity.Memberships[0].TeamID
	service, err := d.CreatePrivateService(ctx, teamID, identityID, "orders", "create-orders", now)
	if err != nil {
		t.Fatal(err)
	}
	visitorID, wrongEmailID, unverifiedID := newID(opaqueid.IdentityPrefix), newID(opaqueid.IdentityPrefix), newID(opaqueid.IdentityPrefix)
	for _, row := range []struct {
		id, email string
		verified  bool
	}{
		{visitorID, "visitor@example.test", true}, {wrongEmailID, "other@example.test", true},
		{unverifiedID, "visitor@example.test", false},
	} {
		exec(`INSERT INTO control.identities(id, kind, display_name, normalized_email, email_verified, created_at, updated_at)
			VALUES ($1, 'authority', 'visitor', $2, $3, $4, $4)`, row.id, row.email, row.verified, now)
	}
	invite, err := d.InvitePrivateServiceVisitor(ctx, service.ID, identityID, "invite", "visitor@example.test", now.Add(time.Hour), now)
	if err != nil || invite.Secret == "" {
		t.Fatalf("create invitation: %+v, %v", invite, err)
	}
	if _, err = d.InvitePrivateServiceVisitor(ctx, service.ID, identityID, "invite", "visitor@example.test", now.Add(time.Hour), now); !errors.Is(err, controlstate.ErrPrivateServiceConflict) {
		t.Fatalf("invitation retry reissued a different one-use secret: %v", err)
	}
	if _, err = d.AcceptPrivateServiceInvitation(ctx, wrongEmailID, invite.Secret, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("different verified email accepted invitation: %v", err)
	}
	if _, err = d.AcceptPrivateServiceInvitation(ctx, unverifiedID, invite.Secret, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("unverified matching email accepted invitation: %v", err)
	}
	grant, err := d.AcceptPrivateServiceInvitation(ctx, visitorID, invite.Secret, now)
	if err != nil || grant.IdentityID != visitorID || grant.InvitationID != invite.ID {
		t.Fatalf("accept invitation: %+v, %v", grant, err)
	}
	if _, err = d.AcceptPrivateServiceInvitation(ctx, visitorID, invite.Secret, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("reused invitation secret: %v", err)
	}
	listed, err := d.ListPrivateServiceInvitations(ctx, service.ID, identityID)
	if err != nil || len(listed) != 1 || listed[0].Secret != "" {
		t.Fatalf("listed invitation leaked secret: %+v, %v", listed, err)
	}

	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: teamID, Kind: "private_service", PrivateServiceID: service.ID},
		Name:  "publisher", Kind: "installed", EditorID: identityID,
		EditorMembershipID: owner.Identity.Memberships[0].ID,
		PolicyRevision:     uint64(owner.Identity.Memberships[0].PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatalf("enroll exact private publisher: %v", err)
	}
	p, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, publicKey, now)
	if err != nil || p.Scope.PrivateServiceID != service.ID || p.Scope.PublicURLID != "" {
		t.Fatalf("private publisher scope = %+v: %v", p, err)
	}
	publisherID, keyID, publisherGrantID := p.ID, p.KeyID, p.GrantID
	publicURLScope := p
	publicURLScope.Scope.Kind, publicURLScope.Scope.PrivateServiceID, publicURLScope.Scope.PublicURLID = "saved_url", "", service.ID
	if _, err = d.PreparePrivateServiceRun(ctx, service.ID, publicURLScope, "wrong-scope", now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("public URL scope selected private service: %v", err)
	}
	for _, relay := range []string{"relay-a", "relay-b"} {
		runID := newID(opaqueid.RelayRunPrefix)
		exec(`INSERT INTO control.relay_services(relay_service_id, relay_address, tls_server_name, created_at, updated_at)
			VALUES ($1, $2, $1, $3, $3)`, relay, relay+":443", now)
		exec(`INSERT INTO control.relay_leases(relay_id, relay_service_id, relay_run_id, relay_lease_revision,
			protocol_version, internal_relay_address, connection_capacity, stream_capacity,
			registered_at, renewed_at, lease_expires_at)
			VALUES ($1, $1, $2, 1, 1, $3, 8, 8, $4, $4, $5)`, relay, runID, relay+":444", now, now.Add(10*time.Minute))
	}
	prepared, err := d.PreparePrivateServiceRun(ctx, service.ID, p, "first", now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.PreparePrivateServiceRun(ctx, service.ID, p, "first", now)
	if err != nil || again.RunID != prepared.RunID || !bytes.Equal(again.Nonce, prepared.Nonce) {
		t.Fatalf("idempotent preparation: %+v, %v", again, err)
	}
	streamKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := tunnelv1.PrivateRunKeyBinding{TeamID: teamID, PrivateServiceID: service.ID, PrivateRunID: prepared.RunID,
		RunNumber: uint64(prepared.RunNumber), PublisherIdentityID: publisherID, PublisherGrantID: publisherGrantID,
		PublisherKeyID: keyID, IdempotencyKey: prepared.IdempotencyKey, BindingNonce: prepared.Nonce, StreamPublicKey: streamKey}
	proofDigest, err := tunnelv1.PrivateRunBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(signingKey, proofDigest)
	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 1
	if _, err = d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, streamKey, badSignature, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("invalid publisher proof bound run: %v", err)
	}
	wrongEnrolledKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyID := newID(opaqueid.PublisherIdentityKeyPrefix)
	exec(`INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at, retired_at)
		VALUES ($1, $2, $3, 2, $4, $4)`, wrongKeyID, publisherID, wrongEnrolledKey, now)
	otherPublisherKey := p
	otherPublisherKey.KeyID = wrongKeyID
	if _, err = d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber,
		otherPublisherKey, streamKey, signature, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("wrong enrolled signing key bound run: %v", err)
	}
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, wrongKey, signature, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("changed TLS public key bound run: %v", err)
	}
	exec(`UPDATE control.relay_leases SET draining=true WHERE relay_id='relay-b'`)
	if _, err = d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, streamKey, signature, now); !errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		t.Fatalf("bound run without two live relay services: %v", err)
	}
	exec(`UPDATE control.relay_leases SET draining=false WHERE relay_id='relay-b'`)
	bound, err := d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, streamKey, signature, now)
	if err != nil || len(bound.Connections) != 2 || !bytes.Equal(bound.PublicKey, streamKey) {
		t.Fatalf("bind run: %+v, %v", bound, err)
	}
	retried, err := d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, streamKey, signature, now)
	if err != nil || retried.Token == bound.Token || retried.Connections[0].Credential != bound.Connections[0].Credential {
		t.Fatalf("retry rotated assignment or failed: %+v, %v", retried, err)
	}
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, bound.Token, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("old run token survived retry: %v", err)
	}
	lease := func(relayID string) controlstate.RelayLeaseIdentity {
		var runID string
		if err := conn.QueryRow(ctx, `SELECT relay_run_id FROM control.relay_leases WHERE relay_id=$1`, relayID).Scan(&runID); err != nil {
			t.Fatal(err)
		}
		return controlstate.RelayLeaseIdentity{RelayServiceID: relayID, RelayID: relayID, RelayRunID: runID, RelayLeaseRevision: 1}
	}
	for index, assignment := range retried.Connections {
		_, err := d.ClaimPrivatePublisherConnection(ctx, assignment.PublisherConnectionID, service.ID,
			prepared.RunID, prepared.RunNumber, assignment.Revision, assignment.Credential,
			lease(assignment.RelayServiceID), now)
		if err != nil {
			t.Fatalf("claim relay %d: %v", index, err)
		}
		_, err = d.ReadyPrivatePublisherConnection(ctx, assignment.PublisherConnectionID, prepared.RunID,
			prepared.RunNumber, assignment.Revision, lease(assignment.RelayServiceID), now)
		if err != nil {
			t.Fatalf("ready relay %d: %v", index, err)
		}
		inventory, _, err := d.ListAvailablePrivateServices(ctx, visitorID, "", now)
		if err != nil || len(inventory) != 1 {
			t.Fatalf("offline inventory after slot %d: %+v, %v", index, inventory, err)
		}
		if (inventory[0].PrivateRunID != "") != (index == 1) {
			t.Fatalf("ready before two relays: %+v", inventory)
		}
	}
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	session, err := d.CreatePrivateConnectorSession(ctx, service.ID, visitorID, now)
	if err != nil {
		t.Fatal(err)
	}
	ingressRun := newID(opaqueid.IngressRunPrefix)
	exec(`INSERT INTO control.ingress_leases(ingress_id, ingress_run_id, ingress_lease_revision,
		protocol_version, connection_capacity, registered_at, renewed_at, lease_expires_at)
		VALUES ('ingress-a', $1, 1, 1, 8, $2, $2, $3)`, ingressRun, now, now.Add(10*time.Minute))
	ingress := controlstate.IngressLeaseIdentity{IngressID: "ingress-a", IngressRunID: ingressRun, IngressLeaseRevision: 1}
	snapshot, err := d.ReadPrivateServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Kind != "upsert" ||
		snapshot.Entries[0].PrivateServiceID != service.ID || len(snapshot.Entries[0].ConnectedRelays) != 2 ||
		!snapshot.Entries[0].ExpiresAt.After(now) {
		t.Fatalf("ID-keyed ready routing snapshot: %+v, %v", snapshot, err)
	}
	exec(`UPDATE control.relay_leases SET lease_expires_at=$1 WHERE relay_id='relay-a'`, now.Add(5*time.Second))
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	late, err := d.ReadPrivateServiceSnapshot(ctx, ingress, now)
	if err != nil || len(late.Entries) != 1 || len(late.Entries[0].ConnectedRelays) != 1 ||
		late.Entries[0].ConnectedRelays[0].RelayID != "relay-b" || !late.Entries[0].ExpiresAt.After(now) {
		t.Fatalf("expiring one projected relay removed surviving relay: %+v, %v", late, err)
	}
	if inventory, _, err := d.ListAvailablePrivateServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].PrivateRunID != prepared.RunID {
		t.Fatalf("one live lease lost visitor inventory: %+v, %v", inventory, err)
	}
	exec(`UPDATE control.relay_leases SET lease_expires_at=$1 WHERE relay_id='relay-a'`, now.Add(10*time.Minute))
	newIdentityKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKeyID := newID(opaqueid.PublisherIdentityKeyPrefix)
	exec(`UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, keyID, now)
	exec(`INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at)
		VALUES ($1, $2, $3, 3, $4)`, newKeyID, publisherID, newIdentityKey, now)
	if _, err = d.PreparePrivateServiceRun(ctx, service.ID, p, "retired-key", now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("retired key prepared another run: %v", err)
	}
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatalf("retired enrollment key ended already-bound run: %v", err)
	}
	afterRotation, err := d.BindPrivateServiceRunKey(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, streamKey, signature, now)
	if err != nil || afterRotation.Token == retried.Token ||
		afterRotation.Connections[0].PublisherConnectionID != retried.Connections[0].PublisherConnectionID ||
		afterRotation.Connections[0].Credential != retried.Connections[0].Credential {
		t.Fatalf("retired key could not retry exact bound run: %+v, %v", afterRotation, err)
	}
	retried = afterRotation
	snapshot, err = d.ReadPrivateServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || len(snapshot.Entries[0].ConnectedRelays) != 2 {
		t.Fatalf("retired-key run lost routing projection: %+v, %v", snapshot, err)
	}
	source := netip.MustParseAddr("192.0.2.10")
	if _, err = d.ClaimPrivateConnectorSession(ctx, ingress, service.ID, session.ID, session.Credential, source, now); err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssuePrivateServiceTicket(ctx, service.ID, session.ID, visitorID, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreatePrivateConnectorSession(ctx, service.ID, visitorID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimPrivateConnectorSession(ctx, ingress, service.ID, other.ID, other.Credential, source, now); err != nil {
		t.Fatal(err)
	}
	claim := func(sessionID string, ip netip.Addr) error {
		_, err := d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, sessionID,
			issued.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, ip, now)
		return err
	}
	if err := claim(other.ID, source); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("ticket crossed sessions: %v", err)
	}
	if err := claim(session.ID, netip.MustParseAddr("192.0.2.11")); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("ticket crossed sources: %v", err)
	}
	if err := claim(session.ID, source); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}
	if err := claim(session.ID, source); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("ticket replayed: %v", err)
	}
	var admittedBefore int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.private_service_tickets WHERE private_run_id=$1 AND consumed_at IS NOT NULL`, prepared.RunID).Scan(&admittedBefore); err != nil {
		t.Fatal(err)
	}
	lost := retried.Connections[0]
	survivor := retried.Connections[1]
	if _, err = d.DisconnectPrivatePublisherConnection(ctx, lost.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, lost.Revision, lease(lost.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailablePrivateServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].PrivateRunID != prepared.RunID {
		t.Fatalf("one surviving relay lost ready inventory: %+v, %v", inventory, err)
	}
	events, err := d.ReadPrivateServiceEvents(ctx, ingress, snapshot.Revision, now)
	if err != nil || len(events.Entries) != 1 || events.Entries[0].Kind != "upsert" || events.Entries[0].PrivateServiceID != service.ID ||
		len(events.Entries[0].ConnectedRelays) != 1 || events.Entries[0].ConnectedRelays[0].PublisherConnectionID != survivor.PublisherConnectionID {
		t.Fatalf("disconnect must publish the surviving relay: %+v, %v", events, err)
	}
	survivorTicket, err := d.IssuePrivateServiceTicket(ctx, service.ID, session.ID, visitorID, now)
	if err != nil {
		t.Fatalf("surviving relay did not admit visitor: %v", err)
	}
	liveVisitorID := newID(opaqueid.VisitorConnectionPrefix)
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, session.ID,
		survivorTicket.Ticket, liveVisitorID, prepared.RunNumber, source, now); err != nil {
		t.Fatalf("one-relay ticket claim: %v", err)
	}
	recheckVisitor := func(sessionID, identity, connectionID string, observed netip.Addr, at time.Time) bool {
		t.Helper()
		decision, err := d.RecheckPrivateServiceVisitor(ctx, ingress, service.ID, prepared.RunID,
			sessionID, identity, connectionID, prepared.RunNumber, observed, at)
		if err != nil {
			t.Fatalf("private live visitor recheck: %v", err)
		}
		if decision.Allowed && (!decision.ValidUntil.After(at) || decision.ValidUntil.After(at.Add(2*time.Minute))) {
			t.Fatalf("unbounded active visitor decision: %+v", decision)
		}
		return decision.Allowed
	}
	if !recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("current consumed visitor was denied")
	}
	if recheckVisitor(other.ID, visitorID, liveVisitorID, source, now) ||
		recheckVisitor(session.ID, identityID, liveVisitorID, source, now) ||
		recheckVisitor(session.ID, visitorID, liveVisitorID, netip.MustParseAddr("192.0.2.11"), now) ||
		recheckVisitor(session.ID, visitorID, newID(opaqueid.VisitorConnectionPrefix), source, now) {
		t.Fatal("cross-session, identity, source, or visitor ID passed live recheck")
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, "ingress-a", now.Add(-10*time.Minute), now.Add(-time.Second))
	if recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("stale ingress lease kept active visitor")
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, "ingress-a", now, now.Add(10*time.Minute))
	shortExpiry := now.Add(5 * time.Second)
	if _, err = d.CreatePrivateServiceGrant(ctx, service.ID, identityID, "short-live", "identity", wrongEmailID, &shortExpiry, now); err != nil {
		t.Fatal(err)
	}
	shortSession, err := d.CreatePrivateConnectorSession(ctx, service.ID, wrongEmailID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimPrivateConnectorSession(ctx, ingress, service.ID, shortSession.ID, shortSession.Credential, source, now); err != nil {
		t.Fatal(err)
	}
	shortTicket, err := d.IssuePrivateServiceTicket(ctx, service.ID, shortSession.ID, wrongEmailID, now)
	if err != nil {
		t.Fatal(err)
	}
	shortVisitor := newID(opaqueid.VisitorConnectionPrefix)
	shortClaim, err := d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, shortSession.ID,
		shortTicket.Ticket, shortVisitor, prepared.RunNumber, source, now)
	if err != nil {
		t.Fatal(err)
	}
	if !shortClaim.ValidUntil.After(now) || shortClaim.ValidUntil.After(shortExpiry) {
		t.Fatalf("initial visitor claim ignored expiring grant: %v, grant %v", shortClaim.ValidUntil, shortExpiry)
	}
	shortValidity, err := d.RecheckPrivateServiceVisitor(ctx, ingress, service.ID, prepared.RunID,
		shortSession.ID, wrongEmailID, shortVisitor, prepared.RunNumber, source, now)
	if err != nil || !shortValidity.Allowed || shortValidity.ValidUntil.After(shortExpiry) {
		t.Fatalf("active recheck ignored expiring grant: %+v, grant %v: %v", shortValidity, shortExpiry, err)
	}
	if !recheckVisitor(shortSession.ID, wrongEmailID, shortVisitor, source, now) ||
		recheckVisitor(shortSession.ID, wrongEmailID, shortVisitor, source, now.Add(6*time.Second)) {
		t.Fatal("grant expiry did not end exactly admitted visitor")
	}
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, session.ID,
		survivorTicket.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("one-relay ticket replayed across visitor streams: %v", err)
	}
	exec(`UPDATE control.relay_leases SET draining=true WHERE relay_id=$1`, lost.RelayServiceID)
	waiting, err := d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || waiting.State != "ready" || waiting.Connections[1].PublisherConnectionID != survivor.PublisherConnectionID || waiting.Connections[1].Revision != survivor.Revision {
		t.Fatalf("waiting for replacement harmed surviving slot: %+v, %v", waiting, err)
	}
	var admittedAfter int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.private_service_tickets WHERE private_run_id=$1 AND consumed_at IS NOT NULL`, prepared.RunID).Scan(&admittedAfter); err != nil || admittedAfter != admittedBefore+2 {
		t.Fatalf("existing visitor admissions changed during relay recovery: before=%d after=%d: %v", admittedBefore, admittedAfter, err)
	}
	exec(`UPDATE control.relay_leases SET draining=false WHERE relay_id=$1`, lost.RelayServiceID)
	repaired, err := d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || repaired.State != "ready" || repaired.Connections[0].Revision != lost.Revision+1 ||
		repaired.Connections[0].PublisherConnectionID == lost.PublisherConnectionID ||
		repaired.Connections[0].RelayServiceID == survivor.RelayServiceID ||
		repaired.Connections[1].PublisherConnectionID != survivor.PublisherConnectionID ||
		repaired.Connections[1].Revision != survivor.Revision {
		t.Fatalf("replacement assignment: %+v, %v", repaired, err)
	}
	if _, err = d.ReadyPrivatePublisherConnection(ctx, survivor.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, survivor.Revision, lease(survivor.RelayServiceID), now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("survivor was replayed as a new assignment: %v", err)
	}
	if _, err = d.ClaimPrivatePublisherConnection(ctx, lost.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, lost.Revision, lost.Credential, lease(lost.RelayServiceID), now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("closed relay assignment reused: %v", err)
	}
	newSlot := repaired.Connections[0]
	if _, err = d.ClaimPrivatePublisherConnection(ctx, newSlot.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, lost.Revision, newSlot.Credential, lease(newSlot.RelayServiceID), now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("new slot accepted old assignment revision: %v", err)
	}
	if _, err = d.ClaimPrivatePublisherConnection(ctx, newSlot.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, newSlot.Revision, newSlot.Credential, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReadyPrivatePublisherConnection(ctx, newSlot.PublisherConnectionID,
		prepared.RunID, prepared.RunNumber, newSlot.Revision, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailablePrivateServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].PrivateRunID != prepared.RunID {
		t.Fatalf("replaced relay did not restore ready inventory: %+v, %v", inventory, err)
	}
	snapshot, err = d.ReadPrivateServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Kind != "upsert" || snapshot.Entries[0].PrivateRunID != prepared.RunID {
		t.Fatalf("replacement routing snapshot: %+v, %v", snapshot, err)
	}
	pending, err := d.IssuePrivateServiceTicket(ctx, service.ID, session.ID, visitorID, now)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, publisherGrantID, now)
	if recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("revoked publisher grant kept active visitor")
	}
	if _, err = d.IssuePrivateServiceTicket(ctx, service.ID, session.ID, visitorID, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("revoked publisher grant issued ticket: %v", err)
	}
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("revoked publisher grant renewed run: %v", err)
	}
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, session.ID,
		pending.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("revoked publisher grant accepted pending ticket: %v", err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=NULL WHERE id=$1`, publisherGrantID)
	if !recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("restored publisher grant lost current visitor")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, publisherID, now)
	if recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("revoked publisher identity kept active visitor")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=NULL WHERE id=$1`, publisherID)
	exec(`UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, visitorID, now)
	if recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("disabled identity kept active visitor")
	}
	exec(`UPDATE control.identities SET disabled_at=NULL WHERE id=$1`, visitorID)
	if err = d.RevokePrivateServiceInvitation(ctx, service.ID, identityID, invite.ID, now); err != nil {
		t.Fatal(err)
	}
	if recheckVisitor(session.ID, visitorID, liveVisitorID, source, now) {
		t.Fatal("revoked visitor grant kept active visitor")
	}
	if list, _, err := d.ListAvailablePrivateServices(ctx, visitorID, "", now); err != nil || len(list) != 0 {
		t.Fatalf("revoked visitor still authorized: %+v, %v", list, err)
	}
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, session.ID,
		pending.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("revoked visitor grant accepted pending ticket: %v", err)
	}
	ownerSession, err := d.CreatePrivateConnectorSession(ctx, service.ID, identityID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimPrivateConnectorSession(ctx, ingress, service.ID, ownerSession.ID,
		ownerSession.Credential, source, now); err != nil {
		t.Fatal(err)
	}
	oldRunTicket, err := d.IssuePrivateServiceTicket(ctx, service.ID, ownerSession.ID, identityID, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerLiveTicket, err := d.IssuePrivateServiceTicket(ctx, service.ID, ownerSession.ID, identityID, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerVisitorID := newID(opaqueid.VisitorConnectionPrefix)
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, ownerSession.ID,
		ownerLiveTicket.Ticket, ownerVisitorID, prepared.RunNumber, source, now); err != nil {
		t.Fatal(err)
	}
	if !recheckVisitor(ownerSession.ID, identityID, ownerVisitorID, source, now) {
		t.Fatal("owner live visitor denied")
	}
	zeroCursor := snapshot.Revision
	if _, err = d.DisconnectPrivatePublisherConnection(ctx, newSlot.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, newSlot.Revision, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.DisconnectPrivatePublisherConnection(ctx, survivor.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, survivor.Revision, lease(survivor.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailablePrivateServices(ctx, identityID, "", now); err != nil || len(inventory) != 1 || inventory[0].PrivateRunID != "" {
		t.Fatalf("zero live relays still available: %+v, %v", inventory, err)
	}
	if recheckVisitor(ownerSession.ID, identityID, ownerVisitorID, source, now) {
		t.Fatal("zero ready slots kept owner visitor")
	}
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, ownerSession.ID,
		oldRunTicket.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, now); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("zero live relays accepted visitor before forwarding: %v", err)
	}
	events, err = d.ReadPrivateServiceEvents(ctx, ingress, zeroCursor, now)
	if err != nil || len(events.Entries) != 2 || events.Entries[0].Kind != "upsert" ||
		len(events.Entries[0].ConnectedRelays) != 1 || events.Entries[1].Kind != "tombstone" {
		t.Fatalf("zero-relay routing events: %+v, %v", events, err)
	}
	recovering, err := d.HeartbeatPrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || recovering.State != "starting" || recovering.Connections[0].Revision <= newSlot.Revision ||
		recovering.Connections[1].Revision <= survivor.Revision {
		t.Fatalf("zero-relay replacement assignments: %+v, %v", recovering, err)
	}
	first := recovering.Connections[0]
	if _, err = d.ClaimPrivatePublisherConnection(ctx, first.PublisherConnectionID, service.ID, prepared.RunID,
		prepared.RunNumber, first.Revision, first.Credential, lease(first.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReadyPrivatePublisherConnection(ctx, first.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, first.Revision, lease(first.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailablePrivateServices(ctx, identityID, "", now); err != nil || len(inventory) != 1 || inventory[0].PrivateRunID != prepared.RunID {
		t.Fatalf("historically ready run did not recover on one relay: %+v, %v", inventory, err)
	}
	if !recheckVisitor(ownerSession.ID, identityID, ownerVisitorID, source, now) {
		t.Fatal("recovered run lost owner visitor")
	}
	if err = d.ClosePrivateServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	if recheckVisitor(ownerSession.ID, identityID, ownerVisitorID, source, now) {
		t.Fatal("closed run kept active visitor")
	}
	p.KeyID = newKeyID
	replacement, err := d.PreparePrivateServiceRun(ctx, service.ID, p, "replacement", now.Add(time.Second))
	if err != nil || replacement.RunNumber != prepared.RunNumber+1 {
		t.Fatalf("replacement: %+v, %v", replacement, err)
	}
	if _, err = d.ClaimPrivateServiceTicket(ctx, ingress, service.ID, prepared.RunID, ownerSession.ID,
		oldRunTicket.Ticket, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, now.Add(time.Second)); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("ticket from closed run survived replacement: %v", err)
	}
	if err = d.RevokePublisherGrant(ctx, teamID, publisherID, publisherGrantID, identityID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.PreparePrivateServiceRun(ctx, service.ID, p, "after-revoke", now.Add(2*time.Second)); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("revoked exact publisher grant prepared another run: %v", err)
	}
	var eventKind string
	if err = conn.QueryRow(ctx, `SELECT kind FROM control.private_service_routing_events WHERE private_service_id=$1 ORDER BY revision DESC LIMIT 1`, service.ID).Scan(&eventKind); err != nil || eventKind != "tombstone" {
		t.Fatalf("publisher revocation routing event = %q, %v", eventKind, err)
	}
}
