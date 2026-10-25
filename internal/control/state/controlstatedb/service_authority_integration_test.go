package controlstatedb_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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
			VALUES ($1, $1, $2, 1, $6, $3, 8, 8, $4, $4, $5)`, relay, runID, relay+":444", now, now.Add(10*time.Minute), tunnelv1.Version)
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
	deviceIDs := map[string]string{}
	deviceKeys := map[string]ed25519.PrivateKey{}
	newSession := func(identity string) controlstate.ConnectorSession {
		t.Helper()
		if deviceIDs[identity] == "" {
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			device, err := d.EnrollVisitorDevice(ctx, identity, public, now)
			if err != nil {
				t.Fatal(err)
			}
			deviceIDs[identity], deviceKeys[identity] = device.ID, key
		}
		assignments, err := d.CreateVisitorIngressAssignments(ctx, identity, deviceIDs[identity], service.ID, newID(opaqueid.IdempotencyPrefix), now)
		if err != nil || len(assignments) != 2 {
			t.Fatalf("dual ingress assignments: %+v %v", assignments, err)
		}
		return assignments[0]
	}
	ingressRun := newID(opaqueid.IngressRunPrefix)
	exec(`INSERT INTO control.ingress_leases(ingress_id, ingress_run_id, ingress_lease_revision,
		protocol_version, connection_capacity, registered_at, renewed_at, lease_expires_at)
		VALUES ('ingress-a', $1, 1, $4, 8, $2, $2, $3)`, ingressRun, now, now.Add(10*time.Minute), tunnelv1.Version)
	ingress := controlstate.IngressLeaseIdentity{IngressID: "ingress-a", IngressRunID: ingressRun, IngressLeaseRevision: 1}
	exec(`UPDATE control.ingress_leases SET connector_address='ingress-a.example:443',connector_tls_server_name='ingress-a.example' WHERE ingress_id='ingress-a'`)
	exec(`INSERT INTO control.ingress_leases(ingress_id,ingress_run_id,ingress_lease_revision,protocol_version,connection_capacity,registered_at,renewed_at,lease_expires_at,connector_address,connector_tls_server_name)
	    VALUES('ingress-b',$1,1,$4,8,$2,$2,$3,'ingress-b.example:443','ingress-b.example')`, newID(opaqueid.IngressRunPrefix), now, now.Add(10*time.Minute), tunnelv1.Version)
	exec(`UPDATE control.ingress_leases SET ingress_pool_id=$1`, controlstate.PrimaryIngressPoolID)
	session := newSession(visitorID)
	snapshot, err := d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Kind != "upsert" ||
		snapshot.Entries[0].ServiceID != service.ID || len(snapshot.Entries[0].ConnectedRelays) != 2 ||
		!snapshot.Entries[0].ExpiresAt.After(now) {
		t.Fatalf("ID-keyed ready routing snapshot: %+v, %v", snapshot, err)
	}
	exec(`UPDATE control.relay_leases SET lease_expires_at=$1 WHERE relay_id='relay-a'`, now.Add(5*time.Second))
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	late, err := d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(late.Entries) != 1 || len(late.Entries[0].ConnectedRelays) != 1 ||
		late.Entries[0].ConnectedRelays[0].RelayID != "relay-b" || !late.Entries[0].ExpiresAt.After(now) {
		t.Fatalf("expiring one projected relay removed surviving relay: %+v, %v", late, err)
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
	snapshot, err = d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || len(snapshot.Entries[0].ConnectedRelays) != 2 {
		t.Fatalf("retired-key run lost routing projection: %+v, %v", snapshot, err)
	}
	source := netip.MustParseAddr("192.0.2.10")
	authenticate := func(session controlstate.ConnectorSession) error {
		hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.ID,
			SessionID: session.ID, Credential: session.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: session.DeviceID, IdentityID: session.IdentityID}, Nonce: bytes.Repeat([]byte{9}, 32), Signature: make([]byte, 64)}
		digest, err := hello.Claim().Digest()
		if err != nil {
			return err
		}
		hello.Signature = ed25519.Sign(deviceKeys[session.IdentityID], digest)
		_, err = d.AuthenticateVisitorConnector(ctx, ingress, hello.Claim(), source, now)
		return err
	}
	if err = authenticate(session); err != nil {
		t.Fatal(err)
	}
	if err = authenticate(session); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("session authentication replay: %v", err)
	}
	issued, err := d.SelectServiceRun(ctx, service.ID, visitorID, deviceIDs[visitorID], now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Endpoint == nil || issued.Endpoint.Hostname != prepared.Hostname || issued.Endpoint.Port != prepared.ServicePort {
		t.Fatal("selection changed the captured managed endpoint")
	}
	other := newSession(visitorID)
	if err = authenticate(other); err != nil {
		t.Fatal(err)
	}
	const issuer = "https://control.example.test"
	if err := d.PrepareVisitorSigningKeys(ctx, issuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	parents := map[string]string{}
	for _, identity := range []string{visitorID, wrongEmailID, identityID} {
		parent := newID(opaqueid.ControlSessionPrefix)
		digest := sha256.Sum256([]byte(parent))
		exec(`INSERT INTO control.control_sessions(id,identity_id,access_token_id,access_token_digest,access_expires_at,refresh_token_id,refresh_token_digest,retry_secret_ciphertext,retry_secret_storage_key_id,refresh_expires_at,created_at,last_refreshed_at)
		    VALUES($1,$2,$1,$3,$5,$1,$3,$4,'fixture',$5,$6,$6)`, parent, identity, digest[:], bytes.Repeat([]byte{1}, 32), now.Add(time.Hour), now)
		parents[identity] = parent
	}
	issue := func(identity string, at time.Time) (controlstate.IssuedVisitorToken, error) {
		principal := controlstate.WithControlPrincipal(ctx, controlstate.ControlPrincipal{IdentityID: identity, SessionID: parents[identity]})
		return d.IssueVisitorToken(principal, issuer, scope, controlstate.DeviceTokenSource{DeviceID: deviceIDs[identity]}, at)
	}
	permission, err := issue(visitorID, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := d.ReadIngressVisitorPolicy(ctx, ingress, scope, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := visitorlease.Decode(policy)
	if err != nil {
		t.Fatal(err)
	}
	admittedVisitorID := newID(opaqueid.VisitorConnectionPrefix)
	message, err := visitortoken.NativeProofMessage(permission.Token, session.ID, admittedVisitorID, prepared.RunID, uint64(prepared.RunNumber), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(deviceKeys[visitorID], message)
	verify := func(subject tunnelv1.VisitorSubject, sessionID, connectionID string) error {
		_, err := visitortoken.VerifyNativeSession(permission.Token, decoded.View, subject, sessionID, connectionID, prepared.RunID, uint64(prepared.RunNumber), 1, nil, deviceKeys[visitorID].Public().(ed25519.PublicKey), signature, now)
		return err
	}
	subject := tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: visitorID, DeviceID: deviceIDs[visitorID]}
	if err := verify(subject, session.ID, admittedVisitorID); err != nil {
		t.Fatal("signed native permission did not retain the actual device", err)
	}
	wrongSubject := subject
	wrongSubject.DeviceID = newID(opaqueid.VisitorDevicePrefix)
	if verify(wrongSubject, session.ID, admittedVisitorID) == nil || verify(subject, other.ID, admittedVisitorID) == nil || verify(subject, session.ID, newID(opaqueid.VisitorConnectionPrefix)) == nil {
		t.Fatal("native proof crossed device, session, or visitor connection")
	}
	canPrepare := func(identity string, at time.Time) bool {
		t.Helper()
		if _, err := d.SelectServiceRun(ctx, service.ID, identity, deviceIDs[identity], at); err != nil {
			return false
		}
		if _, err := d.ReadIngressVisitorPolicy(ctx, ingress, scope, 0, at); err != nil {
			return false
		}
		_, err := issue(identity, at)
		return err == nil
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
	events, err := d.ReadServiceEvents(ctx, ingress, snapshot.Revision, now)
	if err != nil || len(events.Entries) != 1 || events.Entries[0].Kind != "upsert" || events.Entries[0].ServiceID != service.ID ||
		len(events.Entries[0].ConnectedRelays) != 1 || events.Entries[0].ConnectedRelays[0].PublisherConnectionID != survivor.PublisherConnectionID {
		t.Fatalf("disconnect must publish the surviving relay: %+v, %v", events, err)
	}
	if !canPrepare(visitorID, now) {
		t.Fatalf("surviving relay did not admit visitor: %v", err)
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, "ingress-a", now.Add(-10*time.Minute), now.Add(-time.Second))
	if canPrepare(visitorID, now) {
		t.Fatal("stale ingress lease renewed prepared visitor policy")
	}
	exec(`UPDATE control.ingress_leases SET registered_at=$2, renewed_at=$2, lease_expires_at=$3 WHERE ingress_id=$1`, "ingress-a", now, now.Add(10*time.Minute))
	shortExpiry := now.Add(5 * time.Second)
	if _, err = d.CreateServiceGrant(ctx, service.ID, identityID, "short-live", "identity", wrongEmailID, &shortExpiry, now); err != nil {
		t.Fatal(err)
	}
	shortSession := newSession(wrongEmailID)
	if err = authenticate(shortSession); err != nil {
		t.Fatal(err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, wrongEmailID, deviceIDs[wrongEmailID], now)
	if err != nil {
		t.Fatal(err)
	}
	shortPermission, err := issue(wrongEmailID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !shortPermission.Permission.ExpiresAt.After(now) || shortPermission.Permission.ExpiresAt.After(shortExpiry) {
		t.Fatalf("native permission ignored expiring grant: %v, grant %v", shortPermission.Permission.ExpiresAt, shortExpiry)
	}
	if !canPrepare(wrongEmailID, now) || canPrepare(wrongEmailID, now.Add(6*time.Second)) {
		t.Fatal("grant expiry did not end native permission renewal")
	}
	exec(`UPDATE control.relay_leases SET draining=true WHERE relay_id=$1`, lost.RelayServiceID)
	waiting, err := d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now)
	if err != nil || waiting.State != "ready" || waiting.Connections[1].PublisherConnectionID != survivor.PublisherConnectionID || waiting.Connections[1].Revision != survivor.Revision {
		t.Fatalf("waiting for replacement harmed surviving slot: %+v, %v", waiting, err)
	}
	if !canPrepare(visitorID, now) {
		t.Fatal("waiting for a relay replacement lost prepared visitor permission")
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
	snapshot, err = d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Kind != "upsert" || snapshot.Entries[0].ServiceRunID != prepared.RunID {
		t.Fatalf("replacement routing snapshot: %+v, %v", snapshot, err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, visitorID, deviceIDs[visitorID], now)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, publisherGrantID, now)
	if canPrepare(visitorID, now) {
		t.Fatal("revoked publisher grant allowed native preparation")
	}
	if _, err = d.SelectServiceRun(ctx, service.ID, visitorID, deviceIDs[visitorID], now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher grant selected a run: %v", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher grant renewed run: %v", err)
	}
	exec(`UPDATE control.publisher_grants SET revoked_at=NULL WHERE id=$1`, publisherGrantID)
	if !canPrepare(visitorID, now) {
		t.Fatal("restored publisher grant lost prepared visitor permission")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, publisherIdentityID, now)
	if canPrepare(visitorID, now) {
		t.Fatal("revoked publisher identity allowed native preparation")
	}
	exec(`UPDATE control.publisher_identities SET revoked_at=NULL WHERE id=$1`, publisherIdentityID)
	exec(`UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, visitorID, now)
	if canPrepare(visitorID, now) {
		t.Fatal("disabled identity renewed native permission")
	}
	exec(`UPDATE control.identities SET disabled_at=NULL WHERE id=$1`, visitorID)
	if err = d.RevokeServiceInvitation(ctx, service.ID, identityID, invite.ID, now); err != nil {
		t.Fatal(err)
	}
	if canPrepare(visitorID, now) {
		t.Fatal("revoked visitor grant renewed native permission")
	}
	if list, _, err := d.ListAvailableServices(ctx, visitorID, "", now); err != nil || len(list) != 0 {
		t.Fatalf("revoked visitor still authorized: %+v, %v", list, err)
	}
	if _, err := issue(visitorID, now); err == nil {
		t.Fatal("revoked visitor grant issued a new native token")
	}
	ownerSession := newSession(identityID)
	if err = authenticate(ownerSession); err != nil {
		t.Fatal(err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, identityID, deviceIDs[identityID], now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.SelectServiceRun(ctx, service.ID, identityID, deviceIDs[identityID], now)
	if err != nil {
		t.Fatal(err)
	}
	if !canPrepare(identityID, now) {
		t.Fatal("owner native permission denied")
	}
	zeroCursor := snapshot.Revision
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
	if canPrepare(identityID, now) {
		t.Fatal("zero ready slots allowed native preparation")
	}
	events, err = d.ReadServiceEvents(ctx, ingress, zeroCursor, now)
	if err != nil || len(events.Entries) != 2 || events.Entries[0].Kind != "upsert" ||
		len(events.Entries[0].ConnectedRelays) != 1 || events.Entries[1].Kind != "tombstone" {
		t.Fatalf("zero-relay routing events: %+v, %v", events, err)
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
	if !canPrepare(identityID, now) {
		t.Fatal("recovered run lost owner native permission")
	}
	if err = d.CloseServiceRun(ctx, service.ID, prepared.RunID, retried.Token, now); err != nil {
		t.Fatal(err)
	}
	if canPrepare(identityID, now) {
		t.Fatal("closed run allowed native preparation")
	}
	p.KeyID = newKeyID
	replacement, err := d.PrepareServiceRun(ctx, service.ID, p, "replacement", now.Add(time.Second), controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil || replacement.RunNumber != prepared.RunNumber+1 {
		t.Fatalf("replacement: %+v, %v", replacement, err)
	}
	if canPrepare(identityID, now.Add(time.Second)) {
		t.Fatal("closed run selection survived replacement")
	}
	if err = d.RevokePublisherGrant(ctx, teamID, publisherIdentityID, publisherGrantID, identityID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.PrepareServiceRun(ctx, service.ID, p, "after-revoke", now.Add(2*time.Second), controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1}); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked exact publisher grant prepared another run: %v", err)
	}
	var eventKind string
	if err = conn.QueryRow(ctx, `SELECT kind FROM control.service_routing_events WHERE service_id=$1 ORDER BY revision DESC LIMIT 1`, service.ID).Scan(&eventKind); err != nil || eventKind != "tombstone" {
		t.Fatalf("publisher revocation routing event = %q, %v", eventKind, err)
	}
}
