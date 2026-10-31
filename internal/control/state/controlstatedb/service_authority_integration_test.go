package controlstatedb_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
)

func TestIntegrationServiceAuthority(t *testing.T) {
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
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	identityID := owner.Identity.Identity.ID
	teamID := owner.Identity.Memberships[0].TeamID
	service, err := d.CreateServiceAt(ctx, teamID, identityID, "orders", "create-orders", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
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
	invite, err := d.InviteServiceVisitor(ctx, service.ID, identityID, "invite", "visitor@example.test", now.Add(time.Hour), now)
	if err != nil || invite.Secret == "" {
		t.Fatalf("create invitation: %+v, %v", invite, err)
	}
	if retry, err := d.InviteServiceVisitor(ctx, service.ID, identityID, "invite", "visitor@example.test", now.Add(time.Hour), now); err != nil || retry.ID != invite.ID || retry.Secret != "" {
		t.Fatalf("invitation retry lost its ID or reissued a secret: %v", err)
	}
	if _, err = d.AcceptServiceInvitation(ctx, wrongEmailID, invite.Secret, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("different verified email accepted invitation: %v", err)
	}
	if _, err = d.AcceptServiceInvitation(ctx, unverifiedID, invite.Secret, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("unverified matching email accepted invitation: %v", err)
	}
	grant, err := d.AcceptServiceInvitation(ctx, visitorID, invite.Secret, now)
	if err != nil || grant.IdentityID != visitorID || grant.InvitationID != invite.ID {
		t.Fatalf("accept invitation: %+v, %v", grant, err)
	}
	if _, err = d.AcceptServiceInvitation(ctx, visitorID, invite.Secret, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("reused invitation secret: %v", err)
	}
	listed, _, err := d.ListServiceInvitations(ctx, service.ID, identityID, "")
	if err != nil || len(listed) != 1 || listed[0].Secret != "" {
		t.Fatalf("listed invitation leaked secret: %+v, %v", listed, err)
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: teamID, Kind: "service", ServiceID: service.ID},
		Name:  "publisher", Kind: "installed", EditorID: identityID,
		EditorMembershipID: owner.Identity.Memberships[0].ID,
		PolicyRevision:     uint64(owner.Identity.Memberships[0].PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatalf("enroll exact private publisher: %v", err)
	}
	p, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, publicKey, now)
	if err != nil || p.Scope.ServiceID != service.ID || p.Scope.PublicURLID != "" {
		t.Fatalf("private publisher scope = %+v: %v", p, err)
	}
	publisherIdentityID, keyID, publisherGrantID := p.ID, p.KeyID, p.GrantID
	publicURLScope := p
	publicURLScope.Scope.Kind, publicURLScope.Scope.ServiceID, publicURLScope.Scope.PublicURLID = "saved_public_url", "", service.ID
	if _, err = d.PrepareServiceRun(ctx, service.ID, publicURLScope, "wrong-scope", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1}); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("public URL scope selected service: %v", err)
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
	prepared, err := d.PrepareServiceRun(ctx, service.ID, p, "first", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.PrepareServiceRun(ctx, service.ID, p, "first", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil || again.RunID != prepared.RunID || again.Hostname != prepared.Hostname || again.DomainID != prepared.DomainID || again.ServicePort != prepared.ServicePort {
		t.Fatalf("idempotent preparation: %+v, %v", again, err)
	}
	wrongGrant := p
	wrongGrant.GrantID = newID(opaqueid.PublisherGrantPrefix)
	if _, err = d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, wrongGrant, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("another grant started run", err)
	}
	wrongEnrolledKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyID := newID(opaqueid.PublisherIdentityKeyPrefix)
	exec(`INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at, retired_at)
		VALUES ($1, $2, $3, 2, $4, $4)`, wrongKeyID, publisherIdentityID, wrongEnrolledKey, now)
	otherPublisherKey := p
	otherPublisherKey.KeyID = wrongKeyID
	if _, err = d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, otherPublisherKey, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("wrong enrolled signing key bound run: %v", err)
	}
	if _, err = d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber+1, p, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("another run number started", err)
	}
	exec(`UPDATE control.relay_leases SET draining=true WHERE relay_id='relay-b'`)
	if _, err = d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, now); !errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		t.Fatalf("bound run without two live relay services: %v", err)
	}
	exec(`UPDATE control.relay_leases SET draining=false WHERE relay_id='relay-b'`)
	bound, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, now)
	if err != nil || len(bound.Connections) != 2 {
		t.Fatalf("bind run: %+v, %v", bound, err)
	}
	retried, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, now)
	if err != nil || retried.Token == bound.Token || retried.Connections[0].Credential != bound.Connections[0].Credential {
		t.Fatalf("retry rotated assignment or failed: %+v, %v", retried, err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, bound.Token, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("old run token survived retry: %v", err)
	}
	managedcert.Install(t, d, prepared, retried, now)
	lease := func(relayID string) controlstate.RelayLeaseIdentity {
		var runID string
		if err := conn.QueryRow(ctx, `SELECT relay_run_id FROM control.relay_leases WHERE relay_id=$1`, relayID).Scan(&runID); err != nil {
			t.Fatal(err)
		}
		return controlstate.RelayLeaseIdentity{RelayServiceID: relayID, RelayID: relayID, RelayRunID: runID, RelayLeaseRevision: 1}
	}
	for index, assignment := range retried.Connections {
		_, err := d.ClaimServicePublisherConnection(ctx, assignment.PublisherConnectionID, service.ID,
			prepared.RunID, prepared.RunNumber, assignment.Revision, assignment.Credential,
			lease(assignment.RelayServiceID), now)
		if err != nil {
			t.Fatalf("claim relay %d: %v", index, err)
		}
		_, err = d.ReadyServicePublisherConnection(ctx, assignment.PublisherConnectionID, prepared.RunID,
			prepared.RunNumber, assignment.Revision, lease(assignment.RelayServiceID), now)
		if err != nil {
			t.Fatalf("ready relay %d: %v", index, err)
		}
		inventory, _, err := d.ListAvailableServices(ctx, visitorID, "", now)
		if err != nil || len(inventory) != 1 {
			t.Fatalf("offline inventory after slot %d: %+v, %v", index, inventory, err)
		}
		if (inventory[0].ServiceRunID != "") != (index == 1) {
			t.Fatalf("ready before two relays: %+v", inventory)
		}
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.services SET public=true WHERE id=$1`, service.ID)
	ingress := directIngressLease(t, ctx, d, "authority", prepared.ServicePort, now)
	device, certificate := directVisitorCertificate(t, ctx, d, service.ID, visitorID, now)
	source := netip.MustParseAddr("192.0.2.10")
	admit := func() controlstate.DirectVisitorAdmission {
		t.Helper()
		a, err := d.AdmitDirectServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, newID(opaqueid.VisitorConnectionPrefix), prepared.ServicePort, source, now)
		if err != nil {
			t.Fatal("direct admission", err)
		}
		return a
	}
	initial := admit()
	if initial.ServiceID != service.ID || len(initial.Relays) != 2 || !initial.ExpiresAt.After(now) {
		t.Fatal("direct admission lost exact ready run", initial)
	}
	if err := d.CloseDirectServiceVisitor(ctx, ingress, initial.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.relay_leases SET lease_expires_at=$1 WHERE relay_id='relay-a'`, now.Add(5*time.Second))
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	late := admit()
	if len(late.Relays) != 1 || late.Relays[0].RelayID != "relay-b" || !late.ExpiresAt.After(now) {
		t.Fatal("expired relay removed the direct survivor", late)
	}
	if err := d.CloseDirectServiceVisitor(ctx, ingress, late.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailableServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != prepared.RunID {
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
		VALUES ($1, $2, $3, 3, $4)`, newKeyID, publisherIdentityID, newIdentityKey, now)
	if _, err = d.PrepareServiceRun(ctx, service.ID, p, "retired-key", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1}); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("retired key prepared another run: %v", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatalf("retired enrollment key ended already-bound run: %v", err)
	}
	afterRotation, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, p, now)
	if err != nil || afterRotation.Token == retried.Token ||
		afterRotation.Connections[0].PublisherConnectionID != retried.Connections[0].PublisherConnectionID ||
		afterRotation.Connections[0].Credential != retried.Connections[0].Credential {
		t.Fatalf("retired key could not retry exact bound run: %+v, %v", afterRotation, err)
	}
	retried = afterRotation
	current := admit()
	if len(current.Relays) != 2 {
		t.Fatal("retired enrollment key removed live relay", current)
	}
	issued, err := d.SelectServiceRun(ctx, service.ID, visitorID, device, now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Endpoint == nil || issued.Endpoint.Hostname != prepared.Hostname || issued.Endpoint.Port != prepared.ServicePort {
		t.Fatal("selection changed the captured managed endpoint")
	}
	if _, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, newID(opaqueid.VisitorConnectionPrefix), prepared.RunNumber, source, certificate.Raw, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("unreserved direct visitor admitted", err)
	}
	if _, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, current.ConnectionID, prepared.RunNumber, netip.MustParseAddr("192.0.2.11"), certificate.Raw, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("direct admission crossed sources", err)
	}
	if decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, current.ConnectionID, prepared.RunNumber, source, certificate.Raw, now); err != nil || !decision.Allowed {
		t.Fatal("valid direct certificate rejected", err)
	}
	if err := d.PromoteDirectServiceVisitor(ctx, ingress, current.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	_, otherCertificate := directVisitorCertificate(t, ctx, d, service.ID, visitorID, now)
	if _, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, current.ConnectionID, prepared.RunNumber, source, otherCertificate.Raw, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("direct visitor changed its bound device", err)
	}
	var admittedBefore int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.direct_service_visitors WHERE service_run_id=$1`, prepared.RunID).Scan(&admittedBefore); err != nil {
		t.Fatal(err)
	}
	lost := retried.Connections[0]
	survivor := retried.Connections[1]
	if _, err = d.DisconnectServicePublisherConnection(ctx, lost.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, lost.Revision, lease(lost.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailableServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != prepared.RunID {
		t.Fatalf("one surviving relay lost ready inventory: %+v, %v", inventory, err)
	}
	live := admit()
	if len(live.Relays) != 1 || live.Relays[0].PublisherConnectionID != survivor.PublisherConnectionID {
		t.Fatal("disconnect lost surviving direct relay", live)
	}
	survivorSelection, err := d.SelectServiceRun(ctx, service.ID, visitorID, device, now)
	if err != nil {
		t.Fatalf("surviving relay did not admit visitor: %v", err)
	}
	if survivorSelection.ServiceRunID != live.RunID {
		t.Fatal("direct and native selection disagree")
	}
	if decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, live.ConnectionID, prepared.RunNumber, source, certificate.Raw, now); err != nil || !decision.Allowed {
		t.Fatal("one-relay direct authorization", err)
	}
	if err := d.PromoteDirectServiceVisitor(ctx, ingress, live.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	recheckVisitor := func(connectionID string, at time.Time) bool {
		t.Helper()
		decision, err := d.DirectServiceVisitorStatus(ctx, ingress, connectionID, at)
		if errors.Is(err, controlstate.ErrIngressLeaseStale) {
			return false
		}
		if err != nil {
			t.Fatalf("private live visitor recheck: %v", err)
		}
		if decision.State == controlstate.DirectVisitorAllowed && (!decision.ValidUntil.After(at) || decision.ValidUntil.After(at.Add(2*time.Minute))) {
			t.Fatalf("unbounded active visitor decision: %+v", decision)
		}
		return decision.State == controlstate.DirectVisitorAllowed
	}
	if !recheckVisitor(live.ConnectionID, now) {
		t.Fatal("current consumed visitor was denied")
	}
	if status, err := d.DirectServiceVisitorStatus(ctx, ingress, newID(opaqueid.VisitorConnectionPrefix), now); err == nil && status.State == controlstate.DirectVisitorAllowed {
		t.Fatal("another visitor ID passed live recheck")
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, ingress.IngressID, now.Add(-10*time.Minute), now.Add(-time.Second))
	if recheckVisitor(live.ConnectionID, now) {
		t.Fatal("stale ingress lease kept active visitor")
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, ingress.IngressID, now, now.Add(10*time.Minute))
	shortExpiry := now.Add(5 * time.Second)
	if _, err = d.CreateServiceGrant(ctx, service.ID, identityID, "short-live", "identity", wrongEmailID, &shortExpiry, now); err != nil {
		t.Fatal(err)
	}
	_, shortCertificate := directVisitorCertificate(t, ctx, d, service.ID, wrongEmailID, now)
	short := admit()
	shortClaim, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, short.ConnectionID, prepared.RunNumber, source, shortCertificate.Raw, now)
	if err != nil || !shortClaim.Allowed || !shortClaim.ValidUntil.After(now) || shortClaim.ValidUntil.After(shortExpiry) {
		t.Fatalf("initial visitor claim ignored expiring grant: %v, grant %v", shortClaim.ValidUntil, shortExpiry)
	}
	if err := d.PromoteDirectServiceVisitor(ctx, ingress, short.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	shortValidity, err := d.DirectServiceVisitorStatus(ctx, ingress, short.ConnectionID, now)
	if err != nil || shortValidity.State != controlstate.DirectVisitorAllowed || shortValidity.ValidUntil.After(shortExpiry) {
		t.Fatalf("active recheck ignored expiring grant: %+v, grant %v: %v", shortValidity, shortExpiry, err)
	}
	if !recheckVisitor(short.ConnectionID, now) || recheckVisitor(short.ConnectionID, now.Add(6*time.Second)) {
		t.Fatal("grant expiry did not end exactly admitted visitor")
	}
	exec(`UPDATE control.relay_leases SET draining=true WHERE relay_id=$1`, lost.RelayServiceID)
	waiting, err := d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || waiting.State != "ready" || waiting.Connections[1].PublisherConnectionID != survivor.PublisherConnectionID || waiting.Connections[1].Revision != survivor.Revision {
		t.Fatalf("waiting for replacement harmed surviving slot: %+v, %v", waiting, err)
	}
	var admittedAfter int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.direct_service_visitors WHERE service_run_id=$1`, prepared.RunID).Scan(&admittedAfter); err != nil || admittedAfter != admittedBefore+2 {
		t.Fatalf("existing visitor admissions changed during relay recovery: before=%d after=%d: %v", admittedBefore, admittedAfter, err)
	}
	exec(`UPDATE control.relay_leases SET draining=false WHERE relay_id=$1`, lost.RelayServiceID)
	repaired, err := d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || repaired.State != "ready" || repaired.Connections[0].Revision != lost.Revision+1 ||
		repaired.Connections[0].PublisherConnectionID == lost.PublisherConnectionID ||
		repaired.Connections[0].RelayServiceID == survivor.RelayServiceID ||
		repaired.Connections[1].PublisherConnectionID != survivor.PublisherConnectionID ||
		repaired.Connections[1].Revision != survivor.Revision {
		t.Fatalf("replacement assignment: %+v, %v", repaired, err)
	}
	if _, err = d.ReadyServicePublisherConnection(ctx, survivor.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, survivor.Revision, lease(survivor.RelayServiceID), now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("survivor was replayed as a new assignment: %v", err)
	}
	if _, err = d.ClaimServicePublisherConnection(ctx, lost.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, lost.Revision, lost.Credential, lease(lost.RelayServiceID), now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("closed relay assignment reused: %v", err)
	}
	newSlot := repaired.Connections[0]
	if _, err = d.ClaimServicePublisherConnection(ctx, newSlot.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, lost.Revision, newSlot.Credential, lease(newSlot.RelayServiceID), now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("new slot accepted old assignment revision: %v", err)
	}
	if _, err = d.ClaimServicePublisherConnection(ctx, newSlot.PublisherConnectionID, service.ID,
		prepared.RunID, prepared.RunNumber, newSlot.Revision, newSlot.Credential, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReadyServicePublisherConnection(ctx, newSlot.PublisherConnectionID,
		prepared.RunID, prepared.RunNumber, newSlot.Revision, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailableServices(ctx, visitorID, "", now); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != prepared.RunID {
		t.Fatalf("replaced relay did not restore ready inventory: %+v, %v", inventory, err)
	}
	replacementAdmission := admit()
	if replacementAdmission.RunID != prepared.RunID || len(replacementAdmission.Relays) != 2 {
		t.Fatal("replacement direct selection", replacementAdmission)
	}
	if err := d.CloseDirectServiceVisitor(ctx, ingress, replacementAdmission.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, visitorID, device, now)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, publisherGrantID, now)
	if recheckVisitor(live.ConnectionID, now) {
		t.Fatal("revoked publisher grant kept active visitor")
	}
	if _, err = d.SelectServiceRun(ctx, service.ID, visitorID, device, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher grant selected a run: %v", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher grant renewed run: %v", err)
	}
	if _, err = d.AdmitDirectServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, newID(opaqueid.VisitorConnectionPrefix), prepared.ServicePort, source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher grant admitted a new stream: %v", err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=NULL WHERE id=$1`, publisherGrantID)
	if !recheckVisitor(live.ConnectionID, now) {
		t.Fatal("restored publisher grant lost current visitor")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, publisherIdentityID, now)
	if recheckVisitor(live.ConnectionID, now) {
		t.Fatal("revoked publisher identity kept active visitor")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=NULL WHERE id=$1`, publisherIdentityID)
	exec(`UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, visitorID, now)
	if recheckVisitor(live.ConnectionID, now) {
		t.Fatal("disabled identity kept active visitor")
	}
	exec(`UPDATE control.identities SET disabled_at=NULL WHERE id=$1`, visitorID)
	if err = d.RevokeServiceInvitation(ctx, service.ID, identityID, invite.ID, now); err != nil {
		t.Fatal(err)
	}
	if recheckVisitor(live.ConnectionID, now) {
		t.Fatal("revoked visitor grant kept active visitor")
	}
	if list, _, err := d.ListAvailableServices(ctx, visitorID, "", now); err != nil || len(list) != 0 {
		t.Fatalf("revoked visitor still authorized: %+v, %v", list, err)
	}
	if _, err = d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, current.ConnectionID, prepared.RunNumber, source, certificate.Raw, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked visitor grant admitted a new stream: %v", err)
	}
	ownerDevice, ownerCertificate := directVisitorCertificate(t, ctx, d, service.ID, identityID, now)
	oldSelection, err := d.SelectServiceRun(ctx, service.ID, identityID, ownerDevice, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, identityID, ownerDevice, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerVisitor := admit()
	if decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, prepared.RunID, retried.Token, ownerVisitor.ConnectionID, prepared.RunNumber, source, ownerCertificate.Raw, now); err != nil || !decision.Allowed {
		t.Fatal(err)
	}
	if err := d.PromoteDirectServiceVisitor(ctx, ingress, ownerVisitor.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	if !recheckVisitor(ownerVisitor.ConnectionID, now) {
		t.Fatal("owner live visitor denied")
	}
	if _, err = d.DisconnectServicePublisherConnection(ctx, newSlot.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, newSlot.Revision, lease(newSlot.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.DisconnectServicePublisherConnection(ctx, survivor.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, survivor.Revision, lease(survivor.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailableServices(ctx, identityID, "", now); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != "" {
		t.Fatalf("zero live relays still available: %+v, %v", inventory, err)
	}
	if recheckVisitor(ownerVisitor.ConnectionID, now) {
		t.Fatal("zero ready slots kept owner visitor")
	}
	if _, err = d.AdmitDirectServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, newID(opaqueid.VisitorConnectionPrefix), prepared.ServicePort, source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("zero live relays accepted visitor before forwarding: %v", err)
	}
	recovering, err := d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || recovering.State != "starting" || recovering.Connections[0].Revision <= newSlot.Revision ||
		recovering.Connections[1].Revision <= survivor.Revision {
		t.Fatalf("zero-relay replacement assignments: %+v, %v", recovering, err)
	}
	first := recovering.Connections[0]
	if _, err = d.ClaimServicePublisherConnection(ctx, first.PublisherConnectionID, service.ID, prepared.RunID,
		prepared.RunNumber, first.Revision, first.Credential, lease(first.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReadyServicePublisherConnection(ctx, first.PublisherConnectionID, prepared.RunID,
		prepared.RunNumber, first.Revision, lease(first.RelayServiceID), now); err != nil {
		t.Fatal(err)
	}
	if inventory, _, err := d.ListAvailableServices(ctx, identityID, "", now); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != prepared.RunID {
		t.Fatalf("historically ready run did not recover on one relay: %+v, %v", inventory, err)
	}
	if !recheckVisitor(ownerVisitor.ConnectionID, now) {
		t.Fatal("recovered run lost owner visitor")
	}
	if err = d.CloseServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	if recheckVisitor(ownerVisitor.ConnectionID, now) {
		t.Fatal("closed run kept active visitor")
	}
	p.KeyID = newKeyID
	replacement, err := d.PrepareServiceRun(ctx, service.ID, p, "replacement", now.Add(time.Second), controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil || replacement.RunNumber != prepared.RunNumber+1 {
		t.Fatalf("replacement: %+v, %v", replacement, err)
	}
	if _, err = d.AuthorizeServiceClientCertificate(ctx, service.ID, oldSelection.ServiceRunID, retried.Token, ownerVisitor.ConnectionID, oldSelection.RunNumber, source, ownerCertificate.Raw, now.Add(time.Second)); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("closed run selection survived replacement: %v", err)
	}
	if err = d.RevokePublisherGrant(ctx, teamID, publisherIdentityID, publisherGrantID, identityID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.PrepareServiceRun(ctx, service.ID, p, "after-revoke", now.Add(2*time.Second), controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1}); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked exact publisher grant prepared another run: %v", err)
	}
	if _, err = d.AdmitDirectServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, newID(opaqueid.VisitorConnectionPrefix), prepared.ServicePort, source, now.Add(2*time.Second)); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("publisher revocation retained direct admission", err)
	}
}
