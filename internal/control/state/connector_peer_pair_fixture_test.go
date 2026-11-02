package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorPairFixture struct {
	d       *Database
	now     time.Time
	visitor context.Context
	run     ServiceRunState
	request ConnectorPeerPairRequest
	key     ed25519.PrivateKey
	leases  map[string]RelayLease
}

func newConnectorPairFixture(t *testing.T) connectorPairFixture {
	t.Helper()
	f := newConnectorPairRunFixture(t)
	d, now := f.database, f.now
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	visitor := WithControlPrincipal(t.Context(), principal)
	actor := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(visitor, actor.TeamID, principal.IdentityID, "observations", "observations", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "observations", now, ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(visitor, principal.IdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	request := ConnectorPeerPairRequest{ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber,
		PublisherIdentityID: publisher.ID, IdempotencyKey: "observations", Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: principal.IdentityID, DeviceID: device.ID},
		Source: DeviceTokenSource{DeviceID: device.ID}, Action: "create", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(run, f.leases)}
	fixed := connectorPairFixture{d: d, now: now, visitor: visitor, run: run, request: request, key: key, leases: f.leases}
	fixed.sign(t, &fixed.request)
	return fixed
}

func (f connectorPairFixture) sign(t *testing.T, r *ConnectorPeerPairRequest) {
	t.Helper()
	message, err := r.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(f.key, message)
}

func (f connectorPairFixture) create(t *testing.T) ConnectorPeerPair {
	t.Helper()
	pair, err := f.d.PrepareConnectorPeerPair(f.visitor, f.request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func connectorPairSavedAuthority(t *testing.T, d *Database, id string) []byte {
	t.Helper()
	var value []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object('pair',to_jsonb(pair),
	    'claims',(SELECT jsonb_agg(to_jsonb(claim) ORDER BY connection_slot) FROM control.connector_peer_pair_leg_claims claim WHERE pair_id=pair.id),
	    'run',to_jsonb(run),
	    'slots',(SELECT jsonb_agg(to_jsonb(slot) ORDER BY connection_slot) FROM control.service_connection_slots slot WHERE service_run_id=run.id),
	    'parent',(SELECT to_jsonb(parent) FROM control.control_sessions parent WHERE id=pair.parent_control_session_id),
	    'workload',(SELECT to_jsonb(workload) FROM control.workload_sessions workload WHERE id=pair.subject_id),
	    'grant',(SELECT to_jsonb(grant_row) FROM control.publisher_grants grant_row WHERE id=run.publisher_grant_id))
	    FROM control.connector_peer_pairs pair JOIN control.service_runs run ON run.id=pair.service_run_id WHERE pair.id=$1`, id).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
