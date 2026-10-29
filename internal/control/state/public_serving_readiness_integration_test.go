package state

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func servingReadinessPrerequisites(t *testing.T) (*Database, time.Time, PublishRunRequest, map[string]RelayLease) {
	t.Helper()
	d, now, request, leases := newPublishRunPrerequisites(t)
	created := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, created, now)
	request.PublicURLID, request.TeamID, request.ActingIdentityID, request.MembershipID = url.ID, created.TeamID, created.ActingIdentityID, created.MembershipID
	request.CertificateCacheKey, request.CertificateIdentifiers = url.CanonicalHostname, []string{url.CanonicalHostname}
	return d, now, request, leases
}

func newServingReadinessFixture(t *testing.T) publishRunFixture {
	t.Helper()
	d, now, request, leases := servingReadinessPrerequisites(t)
	setup, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return publishRunFixture{d, now, request, setup, leases}
}

func prepareServingPublisher(t *testing.T, f publishRunFixture) {
	t.Helper()
	work := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), true, nil)
	if _, err := f.database.MarkPublicURLCertificateInstalled(t.Context(), f.authentication(), work.ID, *work.NotAfter, f.now); err != nil {
		t.Fatal(err)
	}
	for slot := range f.setup.PublisherConnections {
		claimTestConnection(t, f, slot, f.now)
	}
}

func servingPreparationPending(t *testing.T, f publishRunFixture, now time.Time) {
	t.Helper()
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), now); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatalf("preparation pending: %v", err)
	}
}

func servingAllocation(t *testing.T, f publishRunFixture, owner IngressLeaseIdentity, now time.Time) StreamCapacityAllocation {
	t.Helper()
	a, err := f.database.AllocateStreamCapacity(t.Context(), StreamCapacityRequest{Owner: owner,
		Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: f.setup.PublicURLID}, RunID: f.setup.PublishRunID,
		RunNumber: int64(f.setup.PublishRunNumber), RequestID: "prepare", Capacity: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func observeServingPublisher(t *testing.T, f publishRunFixture, a StreamCapacityAllocation, now time.Time) {
	t.Helper()
	wire, err := f.database.ReadPublisherVisitorPolicy(t.Context(), a.Scope, a.RunID, a.RunNumber, f.setup.PublishRunToken.String(), 0, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	installed := installServingTestPolicy(t, a.Scope, wire, now)
	view, _, _ := installed.Current()
	observed := installed.BoundedAllocations(a.RunID)
	if !slices.ContainsFunc(observed, func(observation controlv1.StreamCapacityObservation) bool { return observation.AllocationId == a.ID }) {
		t.Fatal("publisher did not install the receiver's exact current allocation")
	}
	_, err = f.database.ReadPublisherVisitorPolicy(t.Context(), a.Scope, a.RunID, a.RunNumber, f.setup.PublishRunToken.String(), view.VisitorPolicyRevision, observed, now)
	if err != nil {
		t.Fatal(err)
	}
}

func observeServingIngress(t *testing.T, f publishRunFixture, a StreamCapacityAllocation, now time.Time) {
	t.Helper()
	wire, err := f.database.ReadIngressVisitorPolicy(t.Context(), a.Owner, a.Scope, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	installed := installServingTestPolicy(t, a.Scope, wire, now)
	view, enabled, _ := installed.Current()
	if !enabled {
		t.Fatal("receiver installed a disabled public URL policy")
	}
	var observed []IngressStreamAllocationObservation
	for _, allocation := range installed.BoundedAllocations(a.RunID) {
		if allocation.AllocationId == a.ID {
			observed = append(observed, IngressStreamAllocationObservation{AllocationID: allocation.AllocationId, RunID: allocation.RunId, RunNumber: allocation.RunNumber, ValidUntil: allocation.ValidUntil})
		}
	}
	if len(observed) != 1 {
		t.Fatal("receiver did not install its exact current allocation")
	}
	_, err = f.database.ReadIngressVisitorPolicy(t.Context(), a.Owner, a.Scope, view.VisitorPolicyRevision, now, observed...)
	if err != nil {
		t.Fatal(err)
	}
}

func installServingTestPolicy(t *testing.T, scope visitorscope.Scope, wire controlv1.VisitorPolicyUpdate, now time.Time) *visitorlease.Lease {
	t.Helper()
	lease, err := visitorlease.New(scope, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	request := lease.Begin()
	update, err := visitorlease.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Apply(request, update); err != nil {
		t.Fatal(err)
	}
	return lease
}

func registerServingIngress(t *testing.T, f publishRunFixture, now time.Time) IngressLeaseIdentity {
	t.Helper()
	// retain a live process across preparations, but never resurrect its expired
	// identity when a fixture advances through an idle gap or restart.
	process := fmt.Sprintf("serving-process-%d", now.UnixNano())
	var current string
	err := f.database.pool.QueryRow(t.Context(), `SELECT ingress_run_id FROM control.ingress_leases WHERE ingress_id='serving-ingress' AND lease_expires_at>$1`, now).Scan(&current)
	if err == nil {
		process = current
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{IngressID: "serving-ingress", IngressRunID: process, ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lease.IngressLeaseIdentity
}

func acknowledgeServingRouting(t *testing.T, f publishRunFixture, owner IngressLeaseIdentity, now time.Time) {
	t.Helper()
	snapshot, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), owner, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: snapshot.RoutingTableRevision}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublicServingReadinessRequiresEveryCurrentReceiver(t *testing.T) {
	f := newServingReadinessFixture(t)
	d, now := f.database, f.now
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, now)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	var allocations []StreamCapacityAllocation
	for index := range 2 {
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("prepared-%d", index), IngressRunID: fmt.Sprintf("process-%d", index), ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		a := servingAllocation(t, f, lease.IngressLeaseIdentity, now)
		allocations = append(allocations, a)
		acknowledgeServingRouting(t, f, a.Owner, now)
		observeServingPublisher(t, f, a, now)
	}
	// neither routing installation nor publisher observation installs ingress policy.
	servingPreparationPending(t, f, now)
	observeServingIngress(t, f, allocations[0], now)
	servingPreparationPending(t, f, now)
	observeServingIngress(t, f, allocations[1], now)
	ready, err := d.MarkPublishRunReady(t.Context(), f.authentication(), now)
	if err != nil || ready.ReadyAt == nil || !ready.ReadyAt.Equal(now) || ready.State != PublishRunReady {
		t.Fatalf("prepared run: %+v, %v", ready, err)
	}
	for _, allocation := range allocations {
		acknowledgeServingRouting(t, f, allocation.Owner, now)
	}
	joined, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "prepared-joining", IngressRunID: "joining-process", ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, f, now)
	if _, err := d.BeginIngressDrain(t.Context(), joined.IngressLeaseIdentity, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MarkPublishRunReady(t.Context(), f.authentication(), now); err != nil {
		t.Fatal(err)
	}
	// renewing allocation capacity cannot extend an expired installed-policy acknowledgement.
	later := now.Add(10 * time.Second)
	for _, a := range allocations {
		servingAllocation(t, f, a.Owner, now.Add(9*time.Second))
	}
	servingPreparationPending(t, f, later)
}

func TestIntegrationPublicServingReadinessIsolationAndExactBinding(t *testing.T) {
	a := newServingReadinessFixture(t)
	d, now := a.database, a.now
	first, err := d.GetPublicURLForAuthorization(t.Context(), a.setup.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	url := createTestPublicURL(t, d, CreatePublicURLRequest{TeamID: first.TeamID, DomainID: first.DomainID, MembershipID: first.MembershipID,
		ActingIdentityID: a.request.ActingIdentityID, IdempotencyKey: "prepared-b", RequestDigest: sha256.Sum256([]byte("prepared-b")),
		CanonicalHostname: strings.Replace(first.CanonicalHostname, "demo.", "prepared-b.", 1), Target: first.Target,
		PublicURLScope: first.PublicURLScope, Purpose: first.Purpose, DNSState: PublicURLDNSUnmanaged}, now)
	r := a.request
	r.PublicURLID, r.IdempotencyKey, r.RequestDigest = url.ID, "prepared-b", sha256.Sum256([]byte("prepared-b-run"))
	r.CertificateCacheKey, r.CertificateIdentifiers = url.CanonicalHostname, []string{url.CanonicalHostname}
	setup, err := d.CreatePublishRun(t.Context(), r, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b := publishRunFixture{d, now, r, setup, a.leases}
	for _, f := range []publishRunFixture{a, b} {
		prepareServingPublisher(t, f)
		servingPreparationPending(t, f, now)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, b, now)
	allocation := servingAllocation(t, b, owner, now)
	acknowledgeServingRouting(t, b, owner, now)
	observeServingPublisher(t, b, allocation, now)
	installed, err := d.ReadIngressVisitorPolicy(t.Context(), owner, allocation.Scope, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	observation := IngressStreamAllocationObservation{AllocationID: allocation.ID, RunID: allocation.RunID, RunNumber: allocation.RunNumber, ValidUntil: allocation.ValidUntil}
	for _, test := range []struct {
		name        string
		owner       IngressLeaseIdentity
		scope       visitorscope.Scope
		observation IngressStreamAllocationObservation
	}{
		{"process", IngressLeaseIdentity{owner.IngressID, "other-process", owner.IngressLeaseRevision}, allocation.Scope, observation},
		{"revision", IngressLeaseIdentity{owner.IngressID, owner.IngressRunID, owner.IngressLeaseRevision + 1}, allocation.Scope, observation},
		{"resource", owner, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: a.setup.PublicURLID}, observation},
		{"run", owner, allocation.Scope, IngressStreamAllocationObservation{allocation.ID, a.setup.PublishRunID, allocation.RunNumber, allocation.ValidUntil}},
		{"number", owner, allocation.Scope, IngressStreamAllocationObservation{allocation.ID, allocation.RunID, allocation.RunNumber + 1, allocation.ValidUntil}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := d.ReadIngressVisitorPolicy(t.Context(), test.owner, test.scope, installed.Policy.VisitorPolicyRevision, now, test.observation); err == nil {
				t.Fatal("another resource/run/process supplied serving preparation")
			}
		})
	}
	// an observation accompanying the first fetch must not acknowledge its response.
	if _, err := d.ReadIngressVisitorPolicy(t.Context(), owner, allocation.Scope, 0, now, observation); err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, b, now)
	observeServingIngress(t, b, allocation, now)
	if _, err := d.MarkPublishRunReady(t.Context(), b.authentication(), now); err != nil {
		t.Fatalf("unprepared URL A blocked prepared URL B: %v", err)
	}
	servingPreparationPending(t, a, now)
	if err := d.ClosePublishRun(t.Context(), a.setup.PublishRunID, a.setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.ReadIngressRoutingTableSnapshot(t.Context(), owner, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range snapshot.Entries {
		if entry.PublicURLID == a.setup.PublicURLID {
			t.Fatal("closed starting run left preparatory routing installed")
		}
	}
}

func TestIntegrationPublicServingReadinessStartsGuestClockAndMetricTogether(t *testing.T) {
	d, now, request, leases := servingReadinessPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateGuestTrial(t.Context(), guest, "tunnels.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls(public_url_id,guest_id,created_at) VALUES($1,$2,$3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{d, now, request, setup, leases}
	metrics := observability.New("control")
	t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
	d.Instrument(metrics)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, now)
	servingPreparationPending(t, f, now.Add(2*time.Second))
	var premature bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at IS NOT NULL OR guest.active_ready_at IS NOT NULL OR guest.first_ready_at IS NOT NULL OR guest.used_ready_ns<>0 FROM control.publish_runs run CROSS JOIN control.guest_trials guest WHERE run.id=$1 AND guest.id=$2`, setup.PublishRunID, guest.ID).Scan(&premature); err != nil || premature {
		t.Fatalf("stalled preparation consumed guest ready time: %t, %v", premature, err)
	}
	metricCount := func(want string) {
		t.Helper()
		w := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing ready metric %q", want)
		}
	}
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(w.Body.String(), "tnl_control_publish_runs_ready_total{") {
		t.Fatal("preparation routing emitted a ready metric")
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, f, now)
	allocation := servingAllocation(t, f, owner, now)
	acknowledgeServingRouting(t, f, owner, now)
	observeServingPublisher(t, f, allocation, now)
	observeServingIngress(t, f, allocation, now)
	final := now.Add(3 * time.Second)
	if _, err := d.MarkPublishRunReady(t.Context(), f.authentication(), final); err != nil {
		t.Fatal(err)
	}
	var together bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at=$3 AND guest.active_ready_at=$3 AND guest.first_ready_at=$3 AND guest.used_ready_ns=0 FROM control.publish_runs run CROSS JOIN control.guest_trials guest WHERE run.id=$1 AND guest.id=$2`, setup.PublishRunID, guest.ID, final).Scan(&together); err != nil || !together {
		t.Fatalf("final readiness and guest clocks differ: %t, %v", together, err)
	}
	metricCount("tnl_control_publish_runs_ready_total{tnl_public_url_purpose=\"app\"} 1")
	acknowledgeServingRouting(t, f, owner, final)
	if _, err := d.MarkPublishRunReady(t.Context(), f.authentication(), final); err != nil {
		t.Fatal(err)
	}
	metricCount("tnl_control_publish_runs_ready_total{tnl_public_url_purpose=\"app\"} 1")
}
