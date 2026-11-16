package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationExactGrantHTTPReturnRetainsCapabilityButRequiresNewRun(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	enrollment, err := f.d.IssuePublisherEnrollment(ctx, standaloneEnrollmentRequest(t, f.d, f.local, f.member.IdentityID, "original-http", f.now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access := publisherAccess(t, f.d, publisher, private, "", f.now)
	q := controlstatedb.New(f.d.pool)
	original, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: publisher.GrantID, PublisherIdentityID: publisher.ID})
	if err != nil || !reflect.DeepEqual(original.Protocols, []string{"http"}) || original.RevokedAt.Valid {
		t.Fatal("fixture did not issue an actual unrevoked HTTP-only member grant", original.Protocols, err)
	}
	publication := servicePublicationFixture{database: f.d, now: f.now, service: f.local, publisher: publisher, leases: make(map[string]RelayLease)}
	for _, name := range []string{"restore-a", "restore-b"} {
		lease, err := f.d.RegisterRelay(ctx, relayLifecycleRegistration(name), f.now, 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		publication.leases[lease.RelayServiceID] = lease
	}
	publication.start(t, "original-run", f.now)
	installPrivateTestCertificate(t, f.d, publication.prepared, publication.run, f.now)
	publication.readyConnections(t, f.now)
	if _, err := f.d.HeartbeatServiceRun(ctx, f.local.ID, publication.run.RunID, publication.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 16}); err != nil {
		t.Fatal(err)
	}
	pending, err := f.d.IssuePublisherEnrollment(ctx, standaloneEnrollmentRequest(t, f.d, f.local, f.member.IdentityID, "pending-http", f.now))
	if err != nil {
		t.Fatal(err)
	}
	nativeMetadata := f.local.ServiceMetadata
	nativeMetadata.Protocol = "postgres"
	native, err := f.d.ConfigureService(ctx, f.local.ID, f.member.IdentityID, nativeMetadata, nil, ServiceUpdateConditions{}, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AuthenticatePublisherAccess(ctx, access.Token, "", f.now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("original HTTP token authorized native serving", err)
	}
	for range 2 {
		if err := f.d.CloseServiceRun(ctx, f.local.ID, publication.run.RunID, publication.run.Token, f.now.Add(time.Second)); err != nil {
			t.Fatal("protocol change gated cleanup or its retry", err)
		}
	}
	opened := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: f.local.ID, ServiceKind: "service",
		RunID: publication.run.RunID, RunNumber: publication.run.RunNumber,
		VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), SourceIP: "192.0.2.10",
		EventType: "connection.open", Outcome: "allowed", OccurredAt: f.now}
	closed := opened
	closed.EventID, closed.EventType, closed.Outcome, closed.Reason = serviceaudit.NewID(), "connection.close", "closed", "closed"
	closed.OccurredAt = f.now.Add(2 * time.Second)
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{opened, closed, opened}}
	if result, err := f.d.IngestServiceRunObservations(ctx, f.local.ID, publication.run.RunID, publication.run.Token, publication.run.RunNumber, batch, f.now.Add(2*time.Second)); err != nil || result.Accepted != 2 || result.Duplicates != 1 {
		t.Fatal("native definition gated the original run's retained audit tail", result, err)
	}
	restoredMetadata := native.ServiceMetadata
	restoredMetadata.Protocol = "http"
	restored, err := f.d.ConfigureService(ctx, f.local.ID, f.member.IdentityID, restoredMetadata, nil, ServiceUpdateConditions{}, f.now.Add(3*time.Second))
	if err != nil || restored.TrustRevision != f.local.TrustRevision+2 {
		t.Fatal("HTTP restoration changed management or trust-revision semantics", restored, err)
	}
	current, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: publisher.GrantID, PublisherIdentityID: publisher.ID})
	if err != nil || !reflect.DeepEqual(current, original) {
		t.Fatal("protocol transition revoked, widened, or replaced the actual grant", err)
	}
	authenticated, err := f.d.AuthenticatePublisherAccess(ctx, access.Token, "", f.now.Add(3*time.Second))
	if err != nil || authenticated.GrantID != publisher.GrantID || authenticated.KeyID != publisher.KeyID {
		t.Fatal("HTTP return required another grant or signing key", authenticated, err)
	}
	reexchanged := publisherAccess(t, f.d, publisher, private, "", f.now.Add(3*time.Second))
	if reexchanged.GrantID != publisher.GrantID || reexchanged.KeyID != publisher.KeyID {
		t.Fatal("original signing key did not retain its actual HTTP grant")
	}
	if _, err := f.d.StartServiceRun(ctx, f.local.ID, publication.run.RunID, publication.run.RunNumber, publisher, f.now.Add(3*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("HTTP return revived the old closed run", err)
	}
	next, err := f.d.PrepareServiceRun(ctx, f.local.ID, publisher, "restored-run", f.now.Add(3*time.Second), ServiceRunRequest{Metadata: restored.ServiceMetadata})
	if err != nil || next.RunID == publication.run.RunID || next.RunNumber != publication.run.RunNumber+1 {
		t.Fatal("same actual grant could not prepare a new HTTP run", next, err)
	}
	if _, err := f.d.StartServiceRun(ctx, f.local.ID, next.RunID, next.RunNumber, publisher, f.now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	redeemed, err := f.d.RedeemPublisherEnrollment(ctx, pending.Key, public, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal("unchanged pending HTTP capability could not redeem after HTTP return", err)
	}
	pendingGrant, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: redeemed.GrantID, PublisherIdentityID: redeemed.ID})
	if err != nil || !reflect.DeepEqual(pendingGrant.Protocols, []string{"http"}) {
		t.Fatal("pending enrollment gained capability across the transition", pendingGrant.Protocols, err)
	}
	if err := f.d.RevokePublisherGrant(ctx, f.team, publisher.ID, publisher.GrantID, f.owner, f.now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.d.CloseServiceRun(ctx, f.local.ID, next.RunID, next.Token, f.now.Add(4*time.Second)); err != nil {
		t.Fatal("explicit grant revocation gated exact-token cleanup", err)
	}
	if result, err := f.d.IngestServiceRunObservations(ctx, f.local.ID, publication.run.RunID, publication.run.Token, publication.run.RunNumber, batch, f.now.Add(5*time.Second)); err != nil || result.Accepted != 0 || result.Duplicates != 3 {
		t.Fatal("HTTP return or explicit revocation lost retained audit retries", result, err)
	}
	late := closed
	late.EventID = serviceaudit.NewID()
	late.OccurredAt = f.now.Add(serviceObservationDeliveryGrace + 2*time.Second)
	if _, err := f.d.IngestServiceRunObservations(ctx, f.local.ID, publication.run.RunID, publication.run.Token, publication.run.RunNumber,
		serviceaudit.Batch{Events: []serviceaudit.Observation{late}}, late.OccurredAt); !errors.Is(err, ErrServiceAuditAccess) && !errors.Is(err, ErrServiceAccess) {
		t.Fatal("protocol restoration extended the original audit delivery deadline", err)
	}
}
