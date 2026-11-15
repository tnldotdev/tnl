package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func newGuestTrialForTest(t *testing.T, d *Database, now time.Time) NewGuestTrial {
	t.Helper()
	enableGuestTestIngress(t, d)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	guest.GuestTrial, err = d.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	return guest
}

func enableGuestTestIngress(t *testing.T, d *Database) {
	t.Helper()
	pool, err := d.GetIngressPool(t.Context(), PrimaryIngressPoolID)
	if err != nil {
		t.Fatal(err)
	}
	if pool.State == IngressPoolDisabled {
		if err := d.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func guestCredentialForTest(guest NewGuestTrial) GuestCredential {
	return GuestCredential{Token: guest.Token, SourceIP: guest.SourceIP}
}

func guestOperationTime(guest NewGuestTrial) time.Time {
	// trial creation records elapsed lock time; later fixture requests must not
	// reuse a supplied clock that predates that saved creation.
	return guest.ExpiresAt.Add(-GuestLifetime).Add(time.Second)
}

func guestLoopbackTarget(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return "http://" + listener.Addr().String()
}

type guestServiceFixture struct {
	database   *Database
	now        time.Time
	ctx        context.Context
	guest      NewGuestTrial
	allocation AllocateGuestDemoServiceRequest
	service    ServiceRecord
	publisher  PublisherIdentity
	private    ed25519.PrivateKey
	prep       ServiceRunPreparation
	run        ServiceRunState
	leases     map[string]RelayLease
}

func guestAuthorityFixture(t *testing.T, ready bool, trialAge ...time.Duration) (guestServiceFixture, NewGuestTrial) {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "guest_service")
	createdAt := now
	if len(trialAge) == 1 {
		createdAt = now.Add(-trialAge[0])
	}
	guest := newGuestTrialForTest(t, d, createdAt)
	if next := guestOperationTime(guest); next.After(now) {
		now = next
	}
	f := guestServiceFixture{database: d, now: now, guest: guest,
		ctx: WithPublisherRequestSource(t.Context(), guest.SourceIP), leases: map[string]RelayLease{}}
	for slot := range 2 {
		lease, err := d.RegisterRelay(t.Context(), relayLifecycleRegistration(fmt.Sprintf("guest-%d", slot)), now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.leases[lease.RelayServiceID] = lease
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	f.allocation = AllocateGuestDemoServiceRequest{Credential: guestCredentialForTest(guest), IdempotencyKey: "demo",
		Target: guestLoopbackTarget(t), Now: now}
	var err error
	f.service, err = d.AllocateGuestDemoService(t.Context(), f.allocation)
	if err != nil {
		t.Fatalf("allocate guest service: %v", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.private = private
	f.publisher, err = d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), f.service.ID, public, now)
	if err != nil {
		t.Fatalf("enroll guest publisher: %v", err)
	}
	f.prepareAndStart(t, "first", now)
	if ready {
		f.ready(t, now)
	}
	return f, guest
}

func (f *guestServiceFixture) prepareAndStart(t *testing.T, key string, at time.Time) {
	t.Helper()
	var err error
	f.prep, err = f.database.PrepareServiceRun(f.ctx, f.service.ID, f.publisher, key, at,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata, TrafficDefaults: trafficlimits.Default(), TrafficCeiling: trafficlimits.Ceiling()})
	if err != nil {
		t.Fatalf("prepare guest service run: %v", err)
	}
	f.run, err = f.database.StartServiceRun(f.ctx, f.service.ID, f.prep.RunID, f.prep.RunNumber, f.publisher, at)
	if err != nil {
		t.Fatalf("start guest service run: %v", err)
	}
}

func (f *guestServiceFixture) ready(t *testing.T, at time.Time) {
	t.Helper()
	work := createPlanIssuanceWork(t, f.database, at, PublishRunAuthentication{}, f.prep.CertificatePlan, true, nil,
		planIssuanceOptions{privateRun: &f.run, publisherSource: f.guest.SourceIP, lifetime: time.Hour})
	if err := f.database.MarkServiceCertificateInstalled(f.ctx, f.service.ID, f.run.RunID, f.run.Token,
		work.ID, f.run.RunNumber, *work.NotAfter, at); err != nil {
		t.Fatal(err)
	}
	for _, slot := range f.run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := f.database.ClaimServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.service.ID, f.run.RunID,
			f.run.RunNumber, slot.Revision, slot.Credential, f.guest.SourceIP, lease, at); err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.ReadyServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.run.RunID, f.run.RunNumber, slot.Revision, lease, at); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	token := f.run.Token
	f.run, err = f.heartbeat(at)
	f.run.Token = token
	if err != nil || f.run.State != "ready" {
		t.Fatalf("guest did not become ready: %+v, %v", f.run, err)
	}
}

func (f guestServiceFixture) heartbeat(at time.Time) (ServiceRunState, error) {
	return f.database.HeartbeatServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 32})
}

func (f guestServiceFixture) stored(t *testing.T) controlstatedb.ControlGuestTrial {
	t.Helper()
	row, err := controlstatedb.New(f.database.pool).GetGuestTrialByID(t.Context(), f.guest.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}
