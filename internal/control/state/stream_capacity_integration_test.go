package state

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func publicCapacityFixture(t *testing.T, connections int) (*Database, time.Time, visitorscope.Scope, PublishRunSetup) {
	t.Helper()
	d, now, request, _ := newPublishRunPrerequisites(t)
	created := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, created, now)
	request.PublicURLID, request.TeamID, request.ActingIdentityID, request.MembershipID = url.ID, created.TeamID, created.ActingIdentityID, created.MembershipID
	request.CertificateCacheKey, request.CertificateIdentifiers = url.CanonicalHostname, []string{url.CanonicalHostname}
	run, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if connections != trafficlimits.Default().Connections {
		limits := trafficlimits.Default()
		limits.Connections = connections
		payload, err := json.Marshal(limits)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET traffic_limits=$2 WHERE id=$1`, run.PublishRunID, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	return d, now, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}, run
}

func TestIntegrationPublicCapacityPreparesEachServingIngress(t *testing.T) {
	d, now, scope, run := publicCapacityFixture(t, 32)
	var owners []IngressLeaseIdentity
	for index := range 6 {
		connectorOnly := index == 5
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("capacity-ingress-%d", index), IngressRunID: fmt.Sprintf("process-%d", index),
			ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID, ConnectorOnly: connectorOnly}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, lease.IngressLeaseIdentity)
	}
	for index, owner := range owners {
		connectorOnly := index == 5
		request := StreamCapacityRequest{Owner: owner, Scope: scope, RunID: run.PublishRunID, RunNumber: int64(run.PublishRunNumber), RequestID: fmt.Sprintf("portion-%d", index), Capacity: 8}
		allocation, err := d.AllocateStreamCapacity(t.Context(), request, now)
		if connectorOnly {
			if !errors.Is(err, ErrStreamCapacity) {
				t.Fatal("connector-only ingress reserved public URL capacity", err)
			}
			continue
		}
		want := int32(8)
		if err != nil || allocation.Capacity != want {
			t.Fatalf("ingress %d received %d slots; want %d: %v", index, allocation.Capacity, want, err)
		}
	}
}

func TestIntegrationPublicCapacityOnePreparesBothIngressesAndJoin(t *testing.T) {
	d, now, scope, run := publicCapacityFixture(t, 1)
	var first StreamCapacityAllocation
	var firstRequest StreamCapacityRequest
	for index := range 3 {
		at := now.Add(time.Duration(index) * time.Second)
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("public-one-%d", index), IngressRunID: fmt.Sprintf("process-%d", index),
			ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}, at, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		request := StreamCapacityRequest{Owner: lease.IngressLeaseIdentity, Scope: scope, RunID: run.PublishRunID, RunNumber: int64(run.PublishRunNumber), RequestID: "public-setup", Capacity: 8}
		allocation, err := d.AllocateStreamCapacity(t.Context(), request, at)
		if err != nil || allocation.Capacity != 1 || allocation.PublisherObserved {
			t.Fatal("a public ingress could not independently prepare its one setup slot", allocation, err)
		}
		if index == 0 {
			first, firstRequest = allocation, request
		} else if allocation.ID == first.ID || allocation.ProofKey == first.ProofKey || allocation.Owner == first.Owner {
			t.Fatal("independent ingress reused another process's setup proof")
		}
		if index != 0 {
			if err := d.RetireStreamCapacity(t.Context(), lease.IngressLeaseIdentity, first.ID, at); !errors.Is(err, ErrStreamCapacity) {
				t.Fatal("another ingress retired the original process's public setup", err)
			}
		}
		request.RequestID = "extra-setup"
		if _, err := d.AllocateStreamCapacity(t.Context(), request, at); !errors.Is(err, ErrStreamCapacity) {
			t.Fatal("one process exceeded its local setup bound", err)
		}
	}
	renewed, err := d.AllocateStreamCapacity(t.Context(), firstRequest, now.Add(3*time.Second))
	if err != nil || renewed.ID != first.ID || renewed.ProofKey != first.ProofKey || renewed.Capacity != 1 {
		t.Fatal("joining ingress invalidated the original setup binding", renewed, err)
	}
	if err := d.RetireStreamCapacity(t.Context(), firstRequest.Owner, first.ID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateStreamCapacity(t.Context(), firstRequest, now.Add(4*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retired public setup binding was renewed", err)
	}
	firstRequest.RequestID = "replacement-setup"
	if _, err := d.AllocateStreamCapacity(t.Context(), firstRequest, now.Add(4*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retiring setup proof was forgotten before its deadline", err)
	}
	replacement, err := d.AllocateStreamCapacity(t.Context(), firstRequest, renewed.ValidUntil)
	if err != nil || replacement.ID == first.ID || replacement.ProofKey == first.ProofKey {
		t.Fatal("expired setup proof did not receive a fresh identity", replacement, err)
	}
}

func TestIntegrationPublicCapacityTwoSlotsSkipConnectorOnlyIngress(t *testing.T) {
	d, now, scope, run := publicCapacityFixture(t, 2)
	var publicOwner IngressLeaseIdentity
	for index := range 2 {
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("standalone-ingress-%d", index), IngressRunID: fmt.Sprintf("process-%d", index),
			ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID, ConnectorOnly: index == 1}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			publicOwner = lease.IngressLeaseIdentity
		}
	}
	allocation, err := d.AllocateStreamCapacity(t.Context(), StreamCapacityRequest{Owner: publicOwner, Scope: scope, RunID: run.PublishRunID,
		RunNumber: int64(run.PublishRunNumber), RequestID: "both-public-slots", Capacity: 2}, now)
	if err != nil || allocation.Capacity != 2 {
		t.Fatal("connector-only ingress stranded a public visitor slot", allocation, err)
	}
}

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

func TestIntegrationServiceRunSixteenSlotsPrepareBothIngressPaths(t *testing.T) {
	f, run, owners := capacityFixture(t, 16)
	for index, owner := range owners {
		allocation, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owner, fmt.Sprintf("path-%d", index), 16), f.now)
		if err != nil || allocation.Capacity != 8 {
			t.Fatalf("ingress path %d could not prepare its eight slots: %+v %v", index, allocation, err)
		}
	}
}

func TestIntegrationStreamCapacityScaleOutPreservesLiveGrantsUntilDrain(t *testing.T) {
	f, run, owners := capacityFixture(t, 16)
	d, now := f.database, f.now
	firstRequest := capacityRequest(run, owners[0], "first-path", 16)
	first, err := d.AllocateStreamCapacity(t.Context(), firstRequest, now)
	if err != nil || first.Capacity != 8 {
		t.Fatal("first ingress did not receive its share", err)
	}
	secondRequest := capacityRequest(run, owners[1], "second-path", 16)
	second, err := d.AllocateStreamCapacity(t.Context(), secondRequest, now)
	if err != nil || second.Capacity != 8 {
		t.Fatal("second ingress did not receive its share", err)
	}
	joined, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "capacity-joining", IngressRunID: "joining-process", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []StreamCapacityRequest{firstRequest, secondRequest} {
		previous := first
		if request.Owner.IngressID == owners[1].IngressID {
			previous = second
		}
		renewed, err := d.AllocateStreamCapacity(t.Context(), request, now.Add(time.Second))
		if err != nil || renewed.ID != previous.ID || renewed.Capacity != 8 || renewed.ProofKey != previous.ProofKey {
			t.Fatal("new ingress revoked a held visitor slot", renewed, err)
		}
	}
	newRequest := capacityRequest(run, joined.IngressLeaseIdentity, "joined-path", 16)
	if _, err := d.AllocateStreamCapacity(t.Context(), newRequest, now.Add(2*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("scale-out oversubscribed existing allocations", err)
	}
	if err := d.RetireStreamCapacity(t.Context(), owners[0], first.ID, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllocateStreamCapacity(t.Context(), newRequest, now.Add(3*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("drain reissued slots before the old grant's deadline", err)
	}
	joinedAllocation, err := d.AllocateStreamCapacity(t.Context(), newRequest, now.Add(11*time.Second))
	if err != nil || joinedAllocation.Capacity != 6 {
		t.Fatal("new ingress did not receive its fair share after the old grant drained", joinedAllocation, err)
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
	wire, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, run.Token, 0, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	stillPending, err := d.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil || stillPending.PublisherObserved {
		t.Fatal("returning a snapshot claimed it was already installed", err)
	}
	installed := installServingTestPolicy(t, request.Scope, wire, f.now)
	observations := installed.BoundedAllocations(run.RunID)
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, "wrong-token", wire.Policy.VisitorPolicyRevision, observations, f.now); err == nil {
		t.Fatal("wrong run credential confirmed capacity")
	}
	observations = append(observations, controlv1.StreamCapacityObservation{AllocationId: other.ID, RunId: run.RunID, RunNumber: run.RunNumber, ValidUntil: other.ValidUntil})
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), request.Scope, run.RunID, run.RunNumber, run.Token, wire.Policy.VisitorPolicyRevision, observations, f.now); err != nil {
		t.Fatal(err)
	}
	observed, err := d.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil || !observed.PublisherObserved {
		t.Fatal("installed allocation did not become available in background renewal", err)
	}
	if observed.ProofKey != first.ProofKey || observed.ProofKey == ([32]byte{}) {
		t.Fatal("renewal replaced the reservation proof key")
	}
	var encrypted []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT proof_key_ciphertext FROM control.stream_capacity_allocations WHERE id=$1`, first.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, first.ProofKey[:]) {
		t.Fatal("reservation proof key was not protected in control state", err)
	}
	untouched, err := d.AllocateStreamCapacity(t.Context(), otherRequest, f.now)
	if err != nil || untouched.PublisherObserved {
		t.Fatal("publisher confirmed another resource's allocation", err)
	}
}

func TestIntegrationStreamCapacityProofSurvivesStorageKeyRotation(t *testing.T) {
	f, run, owners := capacityFixture(t, 4)
	d, now, ctx := f.database, f.now, t.Context()
	request := capacityRequest(run, owners[0], "rotate-proof-key", 2)
	first, err := d.AllocateStreamCapacity(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	var before []byte
	var oldID string
	if err := d.pool.QueryRow(ctx, `SELECT proof_key_ciphertext, proof_key_storage_key_id FROM control.stream_capacity_allocations WHERE id=$1`, first.ID).Scan(&before, &oldID); err != nil || oldID != d.storageKey.CurrentID() {
		t.Fatal("allocation did not start under the old storage key", err)
	}
	url := d.pool.Config().ConnString()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotating, err := Open(ctx, url, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining < 1 {
		t.Fatal("completion did not count the old allocation key", err)
	}
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 0 {
		t.Fatal("completed rotation retained old allocation keys", remaining, err)
	}
	var after []byte
	var currentID string
	if err := rotating.pool.QueryRow(ctx, `SELECT proof_key_ciphertext, proof_key_storage_key_id FROM control.stream_capacity_allocations WHERE id=$1`, first.ID).Scan(&after, &currentID); err != nil || currentID != rotating.storageKey.CurrentID() || bytes.Equal(before, after) {
		t.Fatal("allocation proof was not re-encrypted", err)
	}
	reopened, err := Open(ctx, url, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	renewed, err := reopened.AllocateStreamCapacity(ctx, request, now.Add(time.Second))
	if err != nil || renewed.ProofKey != first.ProofKey {
		t.Fatal("renewal lost its proof key after retiring the old storage key", err)
	}
	policy, err := reopened.ReadIngressVisitorPolicy(ctx, owners[0], request.Scope, 0, now.Add(time.Second))
	if err != nil {
		t.Fatal("visitor policy cannot read the rotated allocation", err)
	}
	var found bool
	for _, allocation := range policy.Policy.StreamAllocations {
		if allocation.Id == first.ID && bytes.Equal(allocation.ReservationKey, first.ProofKey[:]) {
			found = true
		}
	}
	if !found {
		t.Fatal("visitor policy lost the exact allocation proof after key rotation")
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
