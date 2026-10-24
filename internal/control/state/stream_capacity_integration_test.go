package state

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func capacityFixture(t *testing.T, capacity int32) (publishRunFixture, ServiceRunState, []IngressLeaseIdentity) {
	t.Helper()
	f := newPublishRunFixture(t)
	run := privateClaimRun(t, f)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET stream_capacity=$2 WHERE id=$1`, run.RunID, capacity); err != nil {
		t.Fatal(err)
	}
	var owners []IngressLeaseIdentity
	for index := range 2 {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("capacity-%d", index), IngressRunID: fmt.Sprintf("process-%d", index), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, f.now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, lease.IngressLeaseIdentity)
	}
	return f, run, owners
}

func TestIntegrationStreamCapacityIncludesIntegrationURLsWithoutVisitorGrants(t *testing.T) {
	for _, purpose := range []PublicURLPurpose{PublicURLPurposeOAuth, PublicURLPurposeWebhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			d, now, runRequest, _ := newPublishRunPrerequisites(t)
			creation := oidcRouteRequest(t, d, now)
			creation.Purpose = purpose
			url := createTestPublicURL(t, d, creation, now)
			runRequest.PublicURLID, runRequest.TeamID, runRequest.ActingIdentityID, runRequest.MembershipID = url.ID, creation.TeamID, creation.ActingIdentityID, creation.MembershipID
			runRequest.CertificateCacheKey, runRequest.CertificateIdentifiers = url.CanonicalHostname, []string{url.CanonicalHostname}
			run, err := d.CreatePublishRun(t.Context(), runRequest, now, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			ingress, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "public-ingress", IngressRunID: "process", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
			if _, err := d.AllocateStreamCapacity(t.Context(), StreamCapacityRequest{Owner: ingress.IngressLeaseIdentity, Scope: scope, RunID: run.PublishRunID, RunNumber: int64(run.PublishRunNumber), RequestID: "integration-url", Capacity: 2}, now); err != nil {
				t.Fatal("integration URL could not prepare encrypted transport", err)
			}
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			session := newOIDCSession(t, d, now)
			ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
			if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now); !errors.Is(err, ErrVisitorPermission) {
				t.Fatal("transport capacity broadened integration URL visitor grants", err)
			}
		})
	}
}

func capacityRequest(run ServiceRunState, owner IngressLeaseIdentity, key string, amount int32) StreamCapacityRequest {
	return StreamCapacityRequest{Owner: owner, Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, RunID: run.RunID, RunNumber: run.RunNumber, RequestID: key, Capacity: amount}
}

func TestIntegrationStreamCapacitySmallRunSharesTwoIngresses(t *testing.T) {
	f, run, owners := capacityFixture(t, 2)
	first, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "first", 2), f.now)
	if err != nil || first.Capacity != 1 {
		t.Fatal("first ingress took the entire small run", first, err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "extra-id", 1), f.now); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("one ingress hoarded a second allocation ID", err)
	}
	other, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "second", 2), f.now)
	if err != nil || other.Capacity != 1 || other.Owner.IngressID == first.Owner.IngressID {
		t.Fatal("second ingress lost its independent small-run slot", other, err)
	}
	replayed, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "first", 2), f.now.Add(time.Second))
	if err != nil || replayed.ID != first.ID || replayed.Capacity != first.Capacity {
		t.Fatal("replaying the first slot spent a sibling's capacity", replayed, err)
	}
}

func TestIntegrationStreamCapacityConcurrentOwnersCannotDoubleSpend(t *testing.T) {
	f, run, owners := capacityFixture(t, 4)
	var workers sync.WaitGroup
	var mu sync.Mutex
	var allocations []StreamCapacityAllocation
	for index := range 12 {
		workers.Go(func() {
			allocation, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[index%2], fmt.Sprintf("request-%d", index), 3), f.now)
			if err != nil && !errors.Is(err, ErrStreamCapacity) {
				t.Errorf("allocate: %v", err)
				return
			}
			if err == nil {
				mu.Lock()
				allocations = append(allocations, allocation)
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	var granted int32
	for _, allocation := range allocations {
		granted += allocation.Capacity
	}
	if granted != 4 {
		t.Fatalf("delegated %d connections from a capacity-4 run", granted)
	}
}

func TestIntegrationStreamCapacityPublisherObservationIsRunBound(t *testing.T) {
	f, run, owners := capacityFixture(t, 4)
	d := f.database
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	request := capacityRequest(run, owners[0], "observed", 2)
	first, err := d.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil || first.PublisherObserved {
		t.Fatal("new allocation was usable before publisher preparation", err)
	}
	otherRun := privateClaimRun(t, f, "other-claims")
	otherRequest := capacityRequest(otherRun, owners[1], "other", 1)
	other, err := d.AllocateStreamCapacity(t.Context(), otherRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, run.Token, 0, nil, f.now); err != nil {
		t.Fatal(err)
	}
	stillPending, err := d.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil || stillPending.PublisherObserved {
		t.Fatal("returning a snapshot claimed it was already installed", err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, "wrong-token", 0, []string{first.ID}, f.now); err == nil {
		t.Fatal("wrong run credential confirmed capacity")
	}
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, run.Token, 0, []string{first.ID, other.ID}, f.now); err != nil {
		t.Fatal(err)
	}
	observed, err := d.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil || !observed.PublisherObserved {
		t.Fatal("installed allocation did not become available in background renewal", err)
	}
	untouched, err := d.AllocateStreamCapacity(t.Context(), otherRequest, f.now)
	if err != nil || untouched.PublisherObserved {
		t.Fatal("publisher confirmed another resource's allocation", err)
	}
}

func TestIntegrationStreamCapacityRetentionKeepsDelayedAuditAttribution(t *testing.T) {
	f, run, owners := capacityFixture(t, 1)
	d := f.database
	allocation, err := d.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "audit-retention", 1), f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		at       time.Time
		retained bool
	}{{allocation.ValidUntil.Add(time.Second), true}, {allocation.ValidUntil.Add(24 * time.Hour), true}, {allocation.ValidUntil.Add(24*time.Hour + time.Second), false}} {
		if _, err := d.ExpireServiceRuns(t.Context(), test.at); err != nil {
			t.Fatal(err)
		}
		var retained bool
		if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.stream_capacity_allocations WHERE id=$1)`, allocation.ID).Scan(&retained); err != nil || retained != test.retained {
			t.Fatalf("allocation audit attribution retained=%t want=%t: %v", retained, test.retained, err)
		}
	}
}

func TestIntegrationStreamCapacityRetirementWaitsForGrantedDeadline(t *testing.T) {
	f, run, owners := capacityFixture(t, 1)
	request := capacityRequest(run, owners[0], "first", 1)
	first, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(time.Second))
	if err != nil || replayed.ID != first.ID || replayed.Capacity != 1 {
		t.Fatal("ambiguous allocation retry spent capacity twice", err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], first.ID, f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "replacement", 2), f.now.Add(3*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retired owner capacity was reissued while still usable", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(3*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retired allocation was renewed", err)
	}
	replacement, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "replacement", 2), replayed.ValidUntil)
	if err != nil || replacement.ID == first.ID {
		t.Fatal("expired allocation identity was reused", err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], replacement.ID, replayed.ValidUntil); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("stale owner released a replacement allocation", err)
	}
}

func TestIntegrationStreamCapacityReductionCannotRenewOversizedGrants(t *testing.T) {
	f, run, owners := capacityFixture(t, 4)
	request := capacityRequest(run, owners[0], "old", 2)
	first, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET stream_capacity=1 WHERE id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("capacity reduction renewed an oversized allocation", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "new", 1), f.now.Add(time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("capacity reduction double-spent a live allocation", err)
	}
	next, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "new", 1), first.ValidUntil)
	if err != nil || next.Capacity != 1 {
		t.Fatal("reduced capacity did not become available after the old deadline", err)
	}
}

func TestIntegrationStreamCapacityRestartCannotReusePriorProcessGrant(t *testing.T) {
	f, run, owners := capacityFixture(t, 1)
	first, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "old-process", 1), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, owners[0].IngressID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	restarted, err := f.database.RegisterIngress(t.Context(), IngressRegistration{IngressID: owners[0].IngressID, IngressRunID: "replacement-process", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, f.now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], first.ID, f.now.Add(2*time.Second)); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("restarted ingress accepted the old process's release", err)
	}
	request := capacityRequest(run, restarted.IngressLeaseIdentity, "new-process", 2)
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(2*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("process replacement reissued capacity before its old deadline", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, first.ValidUntil); err != nil {
		t.Fatal("replacement process could not acquire expired capacity", err)
	}
}

func TestIntegrationStreamCapacityRejectsClosedRunAndDrainingIngress(t *testing.T) {
	for _, boundary := range []string{"run", "ingress"} {
		t.Run(boundary, func(t *testing.T) {
			f, run, owners := capacityFixture(t, 2)
			request := capacityRequest(run, owners[0], "first", 2)
			if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now); err != nil {
				t.Fatal(err)
			}
			if boundary == "run" {
				if err := f.database.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.database.BeginIngressDrain(t.Context(), owners[0], f.now.Add(time.Second), f.now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(2*time.Second)); !errors.Is(err, ErrStreamCapacity) {
				t.Fatal("closed run or draining ingress renewed capacity", err)
			}
		})
	}
}
