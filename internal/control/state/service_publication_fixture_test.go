package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// servicePublicationFixture uses the same enrollment, preparation, and start
// operations as publishers. tests can stop before certificates or relay readiness.
type servicePublicationFixture struct {
	database  *Database
	now       time.Time
	service   ServiceRecord
	publisher PublisherIdentity
	prepared  ServiceRunPreparation
	run       ServiceRunState
	leases    map[string]RelayLease
}

func newServicePublicationFixture(t *testing.T) servicePublicationFixture {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "service_publication")
	session := newOIDCSession(t, d, now)
	member := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	service, err := d.CreateServiceAt(t.Context(), member.TeamID, actor, "web", "web",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: d, now: now, service: service, leases: make(map[string]RelayLease)}
	for slot := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("publication-%d", slot))
		registration.ConnectionCapacity = 100
		lease, err := d.RegisterRelay(t.Context(), registration, now, 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.leases[lease.RelayServiceID] = lease
	}
	enrollment, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
		Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  "test", Kind: "installed", EditorID: actor, EditorMembershipID: member.ID,
		PolicyRevision: uint64(member.PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.publisher, err = d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "first", now)
	return f
}

func (f *servicePublicationFixture) start(t *testing.T, key string, now time.Time) {
	t.Helper()
	var err error
	f.prepared, err = f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, key, now,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	f.run, err = f.database.StartServiceRun(t.Context(), f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, now)
	if err != nil {
		t.Fatal(err)
	}
}

func (f servicePublicationFixture) readyConnections(t *testing.T, now time.Time) {
	t.Helper()
	for index := range f.run.Connections {
		f.readyConnection(t, index, now)
	}
}

func (f servicePublicationFixture) readyConnection(t *testing.T, index int, now time.Time) {
	t.Helper()
	slot := f.run.Connections[index]
	lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
	if _, err := f.database.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.service.ID,
		f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID,
		f.run.RunID, f.run.RunNumber, slot.Revision, lease, now); err != nil {
		t.Fatal(err)
	}
}

func (f servicePublicationFixture) actor(t *testing.T) string {
	t.Helper()
	var actor string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT created_by_identity_id FROM control.services WHERE id=$1`, f.service.ID).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	return actor
}

func (f servicePublicationFixture) sibling(t *testing.T, name string, now time.Time) servicePublicationFixture {
	t.Helper()
	actor := f.actor(t)
	service, err := f.database.CreateServiceAt(t.Context(), f.service.TeamID, actor, name, name, ServicePlacement{}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, f.database, serviceTestAuthority{TeamID: service.TeamID, ActingIdentityID: actor},
		PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	sibling := servicePublicationFixture{database: f.database, now: now, service: service, publisher: publisher, leases: f.leases}
	return sibling
}
