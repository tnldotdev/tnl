package controlstatedb_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationServicePoolsDeviceKeysAndAtomicCapacity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "private_pools")
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
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	now := time.Now().UTC()
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	person, team := owner.Identity.Identity.ID, owner.Identity.Memberships[0].TeamID
	digest := sha256.Sum256([]byte("db.internal\x00system\x00"))
	metadata := controlstate.ServiceMetadata{Protocol: "mysql", PublisherPool: true, TrustRevision: 1, TLS: &controlstate.ServiceTargetTLS{Hostname: "db.internal", System: true, Digest: hex.EncodeToString(digest[:])}}
	service, err := d.CreateServiceAt(ctx, team, person, "common-database", "create", controlstate.ServicePlacement{}, now, metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, relay := range []string{"relay-a", "relay-b"} {
		exec(`INSERT INTO control.relay_services(relay_service_id,relay_address,tls_server_name,created_at,updated_at) VALUES($1,$2,$1,$3,$3)`, relay, relay+":443", now)
		exec(`INSERT INTO control.relay_leases(relay_id,relay_service_id,relay_run_id,relay_lease_revision,protocol_version,internal_relay_address,connection_capacity,stream_capacity,registered_at,renewed_at,lease_expires_at)
		    VALUES($1,$1,$2,1,$6,$3,8,8,$4,$4,$5)`, relay, id(opaqueid.RelayRunPrefix), relay+":444", now, now.Add(time.Hour), tunnelv1.Version)
	}
	relayLease := func(relay string) controlstate.RelayLeaseIdentity {
		t.Helper()
		var run string
		if err := conn.QueryRow(ctx, `SELECT relay_run_id FROM control.relay_leases WHERE relay_id=$1`, relay).Scan(&run); err != nil {
			t.Fatal(err)
		}
		return controlstate.RelayLeaseIdentity{RelayServiceID: relay, RelayID: relay, RelayRunID: run, RelayLeaseRevision: 1}
	}
	var publishers []controlstate.PublisherIdentity
	var runs []controlstate.ServiceRunState
	for _, name := range []string{"publisher-a", "publisher-b"} {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: service.ID}, Name: name, Kind: "installed", EditorID: person, EditorMembershipID: owner.Identity.Memberships[0].ID, PolicyRevision: uint64(owner.Identity.Memberships[0].PolicyRevision), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		approved, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now)
		if err != nil || approved.Protocol != metadata.Protocol || approved.TLS == nil || approved.TLS.Digest != metadata.TLS.Digest {
			t.Fatalf("scoped publisher metadata: %+v %v", approved, err)
		}
		wrong := metadata
		wrong.Protocol = "postgres"
		if _, err = d.PrepareServiceRun(ctx, service.ID, publisher, "wrong", now, wrong); !errors.Is(err, controlstate.ErrServiceConflict) {
			t.Fatalf("mismatched pool protocol admitted: %v", err)
		}
		prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "pool-start", now, metadata)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, slot := range run.Connections {
			lease := relayLease(slot.RelayServiceID)
			if _, err = d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
				t.Fatal(err)
			}
			if _, err = d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
		managedcert.Install(t, d, prepared, run, now)
		if _, err = d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err = d.PrepareServiceRun(ctx, service.ID, publisher, "duplicate", now, metadata); !errors.Is(err, controlstate.ErrServiceConflict) {
			t.Fatalf("same publisher joined twice: %v", err)
		}
		publishers = append(publishers, publisher)
		runs = append(runs, run)
	}
	exec(`UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publishers[1].GrantID, now.Add(time.Second))
	if inventory, _, err := d.ListAvailableServices(ctx, person, "", now.Add(2*time.Second)); err != nil || len(inventory) != 1 || inventory[0].ServiceRunID != runs[0].RunID {
		t.Fatalf("newest expired grant hid healthy pool sibling: %+v %v", inventory, err)
	}
	exec(`UPDATE control.publisher_grants SET expires_at=NULL WHERE id=$1`, publishers[1].GrantID)
	ingress := controlstate.IngressLeaseIdentity{IngressID: "ingress-a", IngressRunID: id(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1}
	exec(`INSERT INTO control.ingress_leases(ingress_id,ingress_run_id,ingress_lease_revision,protocol_version,connection_capacity,registered_at,renewed_at,lease_expires_at) VALUES($1,$2,1,$5,8,$3,$3,$4)`, ingress.IngressID, ingress.IngressRunID, now, now.Add(time.Hour), tunnelv1.Version)
	exec(`UPDATE control.ingress_leases SET connector_address='ingress-a.example:443',connector_tls_server_name='ingress-a.example' WHERE ingress_id='ingress-a'`)
	otherIngress := controlstate.IngressLeaseIdentity{IngressID: "ingress-b", IngressRunID: id(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1}
	exec(`INSERT INTO control.ingress_leases(ingress_id,ingress_run_id,ingress_lease_revision,protocol_version,connection_capacity,registered_at,renewed_at,lease_expires_at,connector_address,connector_tls_server_name)
	    VALUES($1,$2,1,$5,8,$3,$3,$4,'ingress-b.example:443','ingress-b.example')`, otherIngress.IngressID, otherIngress.IngressRunID, now, now.Add(time.Hour), tunnelv1.Version)
	exec(`UPDATE control.ingress_leases SET ingress_pool_id=$1`, controlstate.PrimaryIngressPoolID)
	snapshot, err := d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 2 {
		t.Fatalf("pool snapshot: %+v %v", snapshot, err)
	}
	public, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, person, public, now)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := d.CreateVisitorIngressAssignments(ctx, person, device.ID, service.ID, "startup", now)
	if err != nil || len(assignments) != 2 {
		t.Fatalf("dual ingress assignments: %+v %v", assignments, err)
	}
	if assignments[0].IngressID == assignments[1].IngressID || assignments[0].IngressAddress == assignments[1].IngressAddress {
		t.Fatal("ingress assignments share one process address")
	}
	source := netip.MustParseAddr("192.0.2.10")
	for _, session := range assignments {
		assigned := ingress
		if session.IngressID == otherIngress.IngressID {
			assigned = otherIngress
		}
		hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.ID, SessionID: session.ID, Credential: session.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device.ID, IdentityID: person}, Nonce: bytes.Repeat([]byte{1}, 32), Signature: make([]byte, 64)}
		proof, err := hello.Claim().Digest()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.AuthenticateVisitorConnector(ctx, assigned, hello.Claim(), source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatalf("invalid device signature admitted: %v", err)
		}
		hello.Signature = ed25519.Sign(deviceKey, proof)
		wrongIngress := ingress
		if assigned.IngressID == ingress.IngressID {
			wrongIngress = otherIngress
		}
		if _, err = d.AuthenticateVisitorConnector(ctx, wrongIngress, hello.Claim(), source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatalf("assignment crossed ingress leases: %v", err)
		}
		if _, err = d.AuthenticateVisitorConnector(ctx, assigned, hello.Claim(), source, now); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := d.SelectServiceRun(ctx, service.ID, person, device.ID, now)
	if err != nil || selected.TLS == nil || selected.TLS.Digest != metadata.TLS.Digest {
		t.Fatalf("authorized trust snapshot: %+v %v", selected, err)
	}
	var wg sync.WaitGroup
	results := make(chan controlstate.StreamCapacityAllocation, 2)
	problems := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			requestID, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
			admitted, err := d.AllocateStreamCapacity(ctx, controlstate.StreamCapacityRequest{Owner: ingress, Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, RunID: runs[0].RunID, RunNumber: runs[0].RunNumber, RequestID: requestID, Capacity: 1}, now)
			results <- admitted
			problems <- err
		})
	}
	wg.Wait()
	close(results)
	close(problems)
	allowed := 0
	for err := range problems {
		if err == nil {
			allowed++
		} else if !errors.Is(err, controlstate.ErrStreamCapacity) {
			t.Fatal(err)
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent capacity allocations=%d, want one", allowed)
	}
	var active controlstate.StreamCapacityAllocation
	for result := range results {
		if result.ID != "" {
			active = result
		}
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, runs[0].RunID, runs[0].Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 1, ActiveStreams: 1}); err != nil {
		t.Fatal(err)
	}
	selected, err = d.SelectServiceRun(ctx, service.ID, person, device.ID, now)
	if err != nil || selected.ServiceRunID != runs[1].RunID {
		t.Fatalf("full run selected: %+v %v", selected, err)
	}
	if err = d.RetireStreamCapacity(ctx, ingress, active.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateStreamCapacity(ctx, controlstate.StreamCapacityRequest{Owner: otherIngress, Scope: active.Scope, RunID: active.RunID, RunNumber: active.RunNumber, RequestID: "still-accounted", Capacity: 1}, now); !errors.Is(err, controlstate.ErrStreamCapacity) {
		t.Fatal("retired capacity was reissued before its deadline", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, runs[0].RunID, runs[0].Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	selected, err = d.SelectServiceRun(ctx, service.ID, person, device.ID, now)
	if err != nil || selected.ServiceRunID != runs[0].RunID {
		t.Fatalf("reported closed stream held selection capacity: %+v %v", selected, err)
	}
	if err = d.RevokeVisitorDevice(ctx, person, device.ID, now); err != nil {
		t.Fatal(err)
	}
	const issuer = "https://control.example.test"
	if err := d.PrepareVisitorSigningKeys(ctx, issuer, now); err != nil {
		t.Fatal(err)
	}
	principal := controlstate.WithControlPrincipal(ctx, controlstate.ControlPrincipal{IdentityID: person, SessionID: owner.SessionID})
	if _, err := d.IssueVisitorToken(principal, issuer, active.Scope, controlstate.DeviceTokenSource{DeviceID: device.ID}, now); !errors.Is(err, controlstate.ErrVisitorPermission) {
		t.Fatal("revoked device renewed native permission", err)
	}
	if _, err = d.SelectServiceRun(ctx, service.ID, person, device.ID, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked device selected a run: %v", err)
	}
	if err = d.RevokePublisherGrant(ctx, team, publishers[0].ID, publishers[0].GrantID, person, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetServiceForPublisher(ctx, service.ID, publishers[0], now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher still read service metadata: %v", err)
	}
	snapshot, err = d.ReadServiceSnapshot(ctx, ingress, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].ServiceRunID != runs[1].RunID {
		t.Fatalf("one publisher tombstone removed sibling: %+v %v", snapshot, err)
	}
	var common, slots int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.publisher_service_runs WHERE service_id=$1 AND closed_at IS NULL`, service.ID).Scan(&common); err != nil || common != 1 {
		t.Fatalf("shared runtime runs=%d: %v", common, err)
	}
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.publisher_service_connection_slots WHERE service_id=$1 AND session_open`, service.ID).Scan(&slots); err != nil || slots != 2 {
		t.Fatalf("shared runtime slots=%d: %v", slots, err)
	}
	if state, err := d.HeartbeatServiceRun(ctx, service.ID, runs[1].RunID, runs[1].Token, now, controlstate.ServiceRunHealth{Healthy: false, StreamCapacity: 1}); err != nil || state.State != "starting" {
		t.Fatalf("unhealthy publisher stayed ready: %+v %v", state, err)
	}
	if snapshot, err := d.ReadServiceSnapshot(ctx, ingress, now); err != nil || len(snapshot.Entries) != 0 {
		t.Fatalf("unhealthy publisher retained routing: %+v %v", snapshot, err)
	}
	if state, err := d.HeartbeatServiceRun(ctx, service.ID, runs[1].RunID, runs[1].Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 1}); err != nil || state.State != "ready" {
		t.Fatalf("healthy pool sibling depended on a primary: %+v %v", state, err)
	}
	changed := metadata
	trust := *metadata.TLS
	trust.Hostname = "replacement.internal"
	nextDigest := sha256.Sum256([]byte("replacement.internal\x00system\x00"))
	trust.Digest = hex.EncodeToString(nextDigest[:])
	changed.TLS = &trust
	if _, err = d.PrepareServiceRun(ctx, service.ID, publishers[1], "wrong-trust", now, changed); !errors.Is(err, controlstate.ErrServiceConflict) {
		t.Fatalf("unapproved TLS identity joined pool: %v", err)
	}
	updated, err := d.ConfigureService(ctx, service.ID, person, changed, now)
	if err != nil || updated.TrustRevision != 2 {
		t.Fatalf("immutable trust replacement: %+v %v", updated, err)
	}
	if snapshot, err := d.ReadServiceSnapshot(ctx, ingress, now); err != nil || len(snapshot.Entries) != 0 {
		t.Fatalf("trust replacement retained old run keys: %+v %v", snapshot, err)
	}
	if _, err = d.ConfigureService(ctx, service.ID, person, metadata, now); !errors.Is(err, controlstate.ErrServiceConflict) {
		t.Fatalf("stale trust revision replaced approved trust: %v", err)
	}
	if _, err = d.PrepareServiceRun(ctx, service.ID, publishers[1], "old-trust", now, metadata); !errors.Is(err, controlstate.ErrServiceConflict) {
		t.Fatalf("publisher rejoined with obsolete trust: %v", err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publishers[1], "approved-trust", now, updated.ServiceMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := d.ExpireSavedPublishRuns(ctx, now.Add(3*time.Minute)); err != nil || count != 1 {
		t.Fatalf("shared expiration worker retained prepared private run %s: %d %v", prepared.RunID, count, err)
	}
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM control.publisher_service_connection_slots WHERE service_id=$1 AND session_open`, service.ID).Scan(&slots); err != nil || slots != 0 {
		t.Fatalf("closed private runs retained relay reservations: %d %v", slots, err)
	}
}
