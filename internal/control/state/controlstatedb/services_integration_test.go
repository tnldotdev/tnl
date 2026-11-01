package controlstatedb_test

import (
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
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
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
		    VALUES($1,$1,$2,1,1,$3,8,8,$4,$4,$5)`, relay, id(opaqueid.RelayRunPrefix), relay+":444", now, now.Add(time.Hour))
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
	exec(`UPDATE control.services SET public=true WHERE id=$1`, service.ID)
	port := service.Endpoint.Port
	ingress := directIngressLease(t, ctx, d, "ingress-a", port, now)
	otherIngress := directIngressLease(t, ctx, d, "ingress-b", port, now)
	device, certificate := publicServiceVisitorCertificate(t, ctx, d, service.ID, person, now)
	source := netip.MustParseAddr("192.0.2.10")
	selected, err := d.SelectServiceRun(ctx, service.ID, person, device, now)
	if err != nil || selected.TLS == nil || selected.TLS.Digest != metadata.TLS.Digest {
		t.Fatalf("authorized trust snapshot: %+v %v", selected, err)
	}
	var wg sync.WaitGroup
	results := make(chan controlstate.PublicServiceVisitorAdmission, 2)
	problems := make(chan error, 2)
	// isolate one run's atomic capacity, then restore the eligible pool sibling.
	exec(`UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publishers[1].GrantID, now.Add(time.Second))
	now = now.Add(2 * time.Second)
	for range 2 {
		wg.Go(func() {
			streamID, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
			admitted, err := d.AdmitPublicServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, streamID, port, source, now)
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
		} else if !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatal(err)
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent capacity admissions=%d, want one", allowed)
	}
	var active controlstate.PublicServiceVisitorAdmission
	for result := range results {
		if result.RunID != "" && result.ExpiresAt.After(now) {
			active = result
		}
	}
	exec(`UPDATE control.publisher_grants SET expires_at=NULL WHERE id=$1`, publishers[1].GrantID)
	selected, err = d.SelectServiceRun(ctx, service.ID, person, device, now)
	if err != nil || selected.ServiceRunID != runs[1].RunID {
		t.Fatalf("full run selected: %+v %v", selected, err)
	}
	if _, err = d.AuthorizeServiceClientCertificate(ctx, service.ID, active.RunID, runs[0].Token, active.ConnectionID, active.RunNumber, netip.MustParseAddr("192.0.2.11"), certificate.Raw, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("certificate supplied another source: %v", err)
	}
	if err = d.ClosePublicServiceVisitor(ctx, ingress, active.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	selected, err = d.SelectServiceRun(ctx, service.ID, person, device, now)
	if err != nil || selected.ServiceRunID != runs[0].RunID {
		t.Fatalf("closed stream held capacity: %+v %v", selected, err)
	}
	active, err = d.AdmitPublicServiceVisitor(ctx, otherIngress, controlstate.PrimaryIngressPoolID, id(opaqueid.VisitorConnectionPrefix), port, source, now)
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, run := range runs {
		if run.RunID == active.RunID {
			token = run.Token
		}
	}
	if decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, active.RunID, token, active.ConnectionID, active.RunNumber, source, certificate.Raw, now); err != nil || !decision.Allowed {
		t.Fatal("valid direct certificate denied", err)
	}
	if err = d.PromotePublicServiceVisitor(ctx, otherIngress, active.ConnectionID, now); err != nil {
		t.Fatal(err)
	}
	if status, err := d.PublicServiceVisitorStatus(ctx, ingress, active.ConnectionID, now); err == nil && status.State == controlstate.PublicServiceVisitorAllowed {
		t.Fatal("direct reservation crossed ingress lease")
	}
	if err = d.RevokeVisitorDevice(ctx, person, device, now); err != nil {
		t.Fatal(err)
	}
	validity, err := d.PublicServiceVisitorStatus(ctx, otherIngress, active.ConnectionID, now)
	if err != nil || validity.State == controlstate.PublicServiceVisitorAllowed {
		t.Fatalf("revoked device kept active stream: %+v %v", validity, err)
	}
	if _, err = d.SelectServiceRun(ctx, service.ID, person, device, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked device selected a run: %v", err)
	}
	if err = d.RevokePublisherGrant(ctx, team, publishers[0].ID, publishers[0].GrantID, person, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetServiceForPublisher(ctx, service.ID, publishers[0], now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatalf("revoked publisher still read service metadata: %v", err)
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
	if _, err := d.AdmitPublicServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, id(opaqueid.VisitorConnectionPrefix), port, source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("unhealthy publisher retained admission", err)
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
	if _, err := d.AdmitPublicServiceVisitor(ctx, ingress, controlstate.PrimaryIngressPoolID, id(opaqueid.VisitorConnectionPrefix), port, source, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("trust replacement retained old run keys", err)
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
