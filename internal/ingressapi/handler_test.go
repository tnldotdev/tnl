package ingressapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/ippolicy"
	"github.com/tnldotdev/tnl/internal/problemtype"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const testIngressClusterSecret = "test-ingress-cluster-secret-0123456789"

func TestHandlerRequiresClusterSecret(t *testing.T) {
	h := testIngressHandler(t, &ingressStoreStub{}, time.Now(), nil)
	tests := []struct {
		name          string
		authorization string
	}{
		{name: "missing"},
		{name: "wrong", authorization: "Bearer wrong-ingress-cluster-secret-012345"},
		{name: "malformed", authorization: "Basic " + testIngressClusterSecret},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/ingresses/register", nil)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
			assertIngressProblemType(t, response, "https://tnl.dev/p/unauthenticated")
		})
	}
}

func TestRegisterIngressAuthorizesAndConvertsRequest(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	var got controlstate.IngressRegistration
	var gotNow time.Time
	var gotDuration time.Duration
	store := &ingressStoreStub{registerIngress: func(
		_ context.Context,
		registration controlstate.IngressRegistration,
		registeredAt time.Time,
		leaseDuration time.Duration,
	) (controlstate.IngressLease, error) {
		got, gotNow, gotDuration = registration, registeredAt, leaseDuration
		return controlstate.IngressLease{
			IngressLeaseIdentity: controlstate.IngressLeaseIdentity{
				IngressID: registration.IngressID, IngressRunID: registration.IngressRunID,
				IngressLeaseRevision: 7,
			},
			ProtocolVersion: registration.ProtocolVersion, ConnectionCapacity: registration.ConnectionCapacity,
			RegisteredAt: registeredAt, RenewedAt: registeredAt, LeaseExpiresAt: registeredAt.Add(leaseDuration),
		}, nil
	}}
	body := ingressv1.IngressRegistration{
		IngressId: "ingress-1", IngressRunId: "run-1", ProtocolVersion: 1, ConnectionCapacity: 100,
	}
	response := serveIngressJSON(
		t, testIngressHandler(t, store, now, nil), http.MethodPost,
		"/internal/v1/ingresses/register", body,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got.IngressID != body.IngressId || got.IngressRunID != body.IngressRunId ||
		got.ProtocolVersion != 1 || got.ConnectionCapacity != 100 {
		t.Fatalf("registration = %#v", got)
	}
	if !gotNow.Equal(now) || gotDuration != 30*time.Second {
		t.Fatalf("register timing = %v, %v", gotNow, gotDuration)
	}
	var lease ingressv1.IngressLease
	decodeIngressResponse(t, response, &lease)
	if lease.IngressId != "ingress-1" || lease.IngressLeaseRevision != 7 {
		t.Fatalf("lease = %#v", lease)
	}
}

func TestIngressRoutingTableEventsUseExactLeaseAndLongPoll(t *testing.T) {
	now := time.Now().UTC()
	hashed, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	event := controlstate.IngressRoutingTableEvent{
		RoutingTableRevision: 12, Kind: "public_url_upsert", PublicURLID: "route-1", PublishRunNumber: 3,
		CanonicalHostname: "example.test", EntryRevision: 4, PublicUrlExpiresAt: timePointer(now.Add(time.Minute)),
		CreatedAt: now,
		Projection: controlstate.IngressRoutingTableProjection{
			PublishRunID: "session-1", PublicURLID: "route-1", PublishRunNumber: 3,
			CanonicalHostname: "example.test", PolicyRevision: 4, IPPolicy: controlstate.IPPolicyHashedAllowlist,
			AllowedIPHashes: []ippolicy.Entry{hashed}, IPPolicyKey: [32]byte{1},
			PublicUrlExpiresAt: now.Add(time.Minute),
			PublisherConnections: []controlstate.IngressRoutingTablePublisherConnection{{
				ConnectionSlot: 0, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 2,
				RelayServiceID: "relay-service-1", RelayID: "relay-1", RelayRunID: "run-relay-1",
				RelayLeaseRevision: 5, InternalRelayAddress: "relay.internal:8443",
				TLSServerName: "relay.internal", LeaseExpiresAt: now.Add(time.Minute),
			}},
		},
	}
	var mutex sync.Mutex
	calls := 0
	store := &ingressStoreStub{readRoutingEvents: func(
		_ context.Context,
		identity controlstate.IngressLeaseIdentity,
		after uint64,
		limit int,
		_ time.Time,
	) (controlstate.IngressRoutingTablePage, error) {
		mutex.Lock()
		defer mutex.Unlock()
		calls++
		if identity.IngressID != "ingress-1" || identity.IngressRunID != "run-1" ||
			identity.IngressLeaseRevision != 7 || after != 11 || limit != 8 {
			t.Fatalf("routing request = %#v, after %d, limit %d", identity, after, limit)
		}
		if calls == 1 {
			return controlstate.IngressRoutingTablePage{ThroughRevision: 11, NextRevision: 11}, nil
		}
		return controlstate.IngressRoutingTablePage{
			ThroughRevision: 12, NextRevision: 12, Events: []controlstate.IngressRoutingTableEvent{event},
		}, nil
	}}
	h, err := NewHandler(Config{
		Store: store, ClusterSecrets: testIngressSecrets(t), LeaseDuration: 30 * time.Second,
		RoutingPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := "/internal/v1/ingresses/ingress-1/routing-table/events?ingress_run_id=run-1&ingress_lease_revision=7&after=11&limit=8&wait=1s"
	request := authenticatedIngressRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var page ingressv1.IngressRoutingTablePage
	decodeIngressResponse(t, response, &page)
	if calls != 2 || page.NextRevision != 12 || len(page.Events) != 1 ||
		page.Events[0].Entry.PublishRunId != "session-1" ||
		len(page.Events[0].Entry.PublisherConnections) != 1 {
		t.Fatalf("routing page after %d calls = %#v", calls, page)
	}
	if page.Events[0].Entry.AllowedIpHashes[0].Digest != hashed.Digest ||
		page.Events[0].Entry.PublisherConnections[0].RelayId != "relay-1" {
		t.Fatalf("routing entry = %#v", page.Events[0].Entry)
	}

}

func TestIngressRoutingEventsRequireResnapshotAfterCompaction(t *testing.T) {
	store := &ingressStoreStub{readRoutingEvents: func(
		context.Context, controlstate.IngressLeaseIdentity, uint64, int, time.Time,
	) (controlstate.IngressRoutingTablePage, error) {
		return controlstate.IngressRoutingTablePage{
			ThroughRevision: 20, RetainedAfterRevision: 15, ResnapshotRequired: true,
		}, nil
	}}
	h := testIngressHandler(t, store, time.Now(), nil)
	request := authenticatedIngressRequest(
		http.MethodGet,
		"/internal/v1/ingresses/ingress-1/routing-table/events?ingress_run_id=run-1&ingress_lease_revision=7&after=11&wait=0s",
		nil,
	)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("resnapshot status = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
	assertIngressProblemType(t, response, "https://tnl.dev/p/routing-table-resnapshot-required")
}

func TestReportIngressUsageConvertsCumulativeReports(t *testing.T) {
	now := time.Now().UTC()
	var gotIdentity controlstate.IngressLeaseIdentity
	var gotBatch controlstate.IngressUsageBatch
	store := &ingressStoreStub{reportUsage: func(
		_ context.Context,
		identity controlstate.IngressLeaseIdentity,
		batch controlstate.IngressUsageBatch,
		receivedAt time.Time,
	) error {
		gotIdentity, gotBatch = identity, batch
		if !receivedAt.Equal(now) {
			t.Fatalf("received at = %v, want %v", receivedAt, now)
		}
		return nil
	}}
	body := ingressv1.IngressUsageReportBatch{
		IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7,
		ObservedThrough: &now, Complete: true,
		Reports: []ingressv1.IngressUsageReport{{
			PublicUrlId: "route-1", PublishRunNumber: 3, BucketStart: now.Add(-time.Minute), BucketEnd: now,
			ObservedThrough: now, ReportRevision: 2, ConnectionAttempts: 10, PolicyDenials: 1, CapacityDenials: 2,
			VisitorStreamOpenFailures: 3, SuccessfulStreams: 4, ConnectionNanoseconds: 5,
			IngressBytes: 6, EgressBytes: 7, HistogramData: []byte{1, 2, 3}, Final: true,
		}},
	}
	response := serveIngressJSON(
		t, testIngressHandler(t, store, now, nil), http.MethodPost,
		"/internal/v1/ingresses/ingress-1/usage-reports", body,
	)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusNoContent, response.Body.String())
	}
	if gotIdentity.IngressID != "ingress-1" || gotIdentity.IngressRunID != "run-1" ||
		gotIdentity.IngressLeaseRevision != 7 || len(gotBatch.Reports) != 1 ||
		gotBatch.ObservedThrough == nil || !gotBatch.ObservedThrough.Equal(now) || !gotBatch.Complete {
		t.Fatalf("usage request = %#v, %#v", gotIdentity, gotBatch)
	}
	got := gotBatch.Reports[0]
	if got.PublicURLID != "route-1" || got.PublishRunNumber != 3 || got.ReportRevision != 2 ||
		got.ConnectionAttempts != 10 || got.PolicyDenials != 1 || got.CapacityDenials != 2 ||
		got.VisitorStreamOpenFailures != 3 || got.SuccessfulStreams != 4 || got.ConnectionNanoseconds != 5 ||
		got.IngressBytes != 6 || got.EgressBytes != 7 || !got.ObservedThrough.Equal(now) ||
		!bytes.Equal(got.HistogramData, []byte{1, 2, 3}) || !got.Final {
		t.Fatalf("usage report = %#v", got)
	}
}

func TestObservePublicURLRecoveryUsesExactIngressLease(t *testing.T) {
	now := time.Now().UTC()
	var gotIdentity controlstate.IngressLeaseIdentity
	store := &ingressStoreStub{observeRecovery: func(
		_ context.Context,
		identity controlstate.IngressLeaseIdentity,
		publicURLID string,
		publishRunNumber, recoveryEpisodeID uint64,
		observedAt time.Time,
	) (controlstate.PublicURLRecoveryObservation, error) {
		gotIdentity = identity
		if publicURLID != "route-1" || publishRunNumber != 3 || recoveryEpisodeID != 9 || !observedAt.Equal(now) {
			t.Fatalf("recovery request = %q, %d, %d, %v", publicURLID, publishRunNumber, recoveryEpisodeID, observedAt)
		}
		return controlstate.PublicURLRecoveryObservation{
			RecoveryEpisodeID: recoveryEpisodeID, PublicURLID: publicURLID, PublishRunNumber: publishRunNumber,
			OpenedAt: now.Add(-time.Second), ObservedAt: now, ObservedSeconds: 1,
		}, nil
	}}
	body := ingressv1.PublicURLRecoveryObservationRequest{
		IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7,
		PublicUrlId: "route-1", PublishRunNumber: 3, ObservedAt: now,
	}
	response := serveIngressJSON(
		t, testIngressHandler(t, store, now, nil), http.MethodPost,
		"/internal/v1/ingresses/ingress-1/public-url-recovery/9/observed", body,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if gotIdentity.IngressID != "ingress-1" || gotIdentity.IngressRunID != "run-1" ||
		gotIdentity.IngressLeaseRevision != 7 {
		t.Fatalf("ingress identity = %#v", gotIdentity)
	}
}

func TestIngressStoreErrorsHaveStableProblems(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name        string
		err         error
		status      int
		problemType string
	}{
		{name: "lease stale", err: controlstate.ErrIngressLeaseStale, status: http.StatusConflict, problemType: "ingress_lease_stale"},
		{name: "invalid usage", err: controlstate.ErrIngressUsageReportInvalid, status: http.StatusBadRequest, problemType: "invalid_usage_report"},
		{name: "usage route missing", err: controlstate.ErrIngressUsagePublicURLNotFound, status: http.StatusNotFound, problemType: "usage_route_not_found"},
		{name: "usage conflict", err: controlstate.ErrIngressUsageReportConflict, status: http.StatusConflict, problemType: "usage_report_conflict"},
		{name: "bucket finalized", err: controlstate.ErrPublicURLUsageBucketFinalized, status: http.StatusConflict, problemType: "usage_bucket_finalized"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &ingressStoreStub{reportUsage: func(
				context.Context, controlstate.IngressLeaseIdentity, controlstate.IngressUsageBatch, time.Time,
			) error {
				return test.err
			}}
			body := ingressv1.IngressUsageReportBatch{
				IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7,
				Reports: []ingressv1.IngressUsageReport{{
					PublicUrlId: "route-1", PublishRunNumber: 1, BucketStart: now.Add(-time.Minute), BucketEnd: now,
					ObservedThrough: now, ReportRevision: 1, HistogramData: []byte{},
				}},
			}
			response := serveIngressJSON(
				t, testIngressHandler(t, store, now, nil), http.MethodPost,
				"/internal/v1/ingresses/ingress-1/usage-reports", body,
			)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			wire, err := ingressv1.ParseReportIngressUsageResponse(response.Result())
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			err = client.ReportIngressUsage(t.Context(), body.IngressId, body)
			var direct *serviceapi.ProblemError
			if !errors.As(err, &direct) || direct.Status != wire.StatusCode() || wire.ApplicationproblemJSONDefault == nil ||
				direct.Type != wire.ApplicationproblemJSONDefault.Type || direct.Title != wire.ApplicationproblemJSONDefault.Title ||
				direct.Detail != wire.ApplicationproblemJSONDefault.Detail {
				t.Fatalf("direct problem differs from HTTP: %#v, %v; HTTP %#v", direct, err, wire)
			}
			assertIngressProblemType(t, response, problemtype.URL(test.problemType))
		})
	}
}

func testIngressHandler(t *testing.T, store Store, now time.Time, report func(error)) http.Handler {
	t.Helper()
	h, err := NewHandler(Config{
		Store: store, ClusterSecrets: testIngressSecrets(t), LeaseDuration: 30 * time.Second,
		Now: func() time.Time { return now }, Report: report,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testIngressSecrets(t *testing.T) serviceapi.BearerSecrets {
	t.Helper()
	secrets, err := serviceapi.NewBearerSecrets(testIngressClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	return secrets
}

func serveIngressJSON(
	t *testing.T,
	h http.Handler,
	method, target string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedIngressRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func authenticatedIngressRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer "+testIngressClusterSecret)
	return request
}

func decodeIngressResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatal(err)
	}
}

func assertIngressProblemType(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var problem ingressv1.Problem
	decodeIngressResponse(t, response, &problem)
	if problem.Type != want {
		t.Fatalf("problem type = %q, want %q", problem.Type, want)
	}
}

func timePointer(value time.Time) *time.Time { return &value }

type ingressStoreStub struct {
	registerIngress     func(context.Context, controlstate.IngressRegistration, time.Time, time.Duration) (controlstate.IngressLease, error)
	renewIngress        func(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error)
	beginIngressDrain   func(context.Context, controlstate.IngressLeaseIdentity, time.Time, time.Time) (controlstate.IngressLease, error)
	readRoutingSnapshot func(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressRoutingTableSnapshot, error)
	readRoutingEvents   func(context.Context, controlstate.IngressLeaseIdentity, uint64, int, time.Time) (controlstate.IngressRoutingTablePage, error)
	reportUsage         func(context.Context, controlstate.IngressLeaseIdentity, controlstate.IngressUsageBatch, time.Time) error
	observeRecovery     func(context.Context, controlstate.IngressLeaseIdentity, string, uint64, uint64, time.Time) (controlstate.PublicURLRecoveryObservation, error)
}

func (s *ingressStoreStub) RegisterIngress(
	ctx context.Context, registration controlstate.IngressRegistration, now time.Time, duration time.Duration,
) (controlstate.IngressLease, error) {
	return s.registerIngress(ctx, registration, now, duration)
}

func (s *ingressStoreStub) RenewIngress(
	ctx context.Context, renewal controlstate.IngressRenewal, now time.Time, duration time.Duration,
) (controlstate.IngressLease, error) {
	return s.renewIngress(ctx, renewal, now, duration)
}

func (s *ingressStoreStub) BeginIngressDrain(
	ctx context.Context, identity controlstate.IngressLeaseIdentity, now, deadline time.Time,
) (controlstate.IngressLease, error) {
	return s.beginIngressDrain(ctx, identity, now, deadline)
}

func (s *ingressStoreStub) ReadIngressRoutingTableSnapshot(
	ctx context.Context, identity controlstate.IngressLeaseIdentity, now time.Time,
) (controlstate.IngressRoutingTableSnapshot, error) {
	return s.readRoutingSnapshot(ctx, identity, now)
}

func (s *ingressStoreStub) ReadIngressRoutingTableEvents(
	ctx context.Context, identity controlstate.IngressLeaseIdentity, after uint64, limit int, now time.Time,
) (controlstate.IngressRoutingTablePage, error) {
	return s.readRoutingEvents(ctx, identity, after, limit, now)
}

func (s *ingressStoreStub) ReportIngressUsage(
	ctx context.Context,
	identity controlstate.IngressLeaseIdentity,
	batch controlstate.IngressUsageBatch,
	now time.Time,
) error {
	return s.reportUsage(ctx, identity, batch, now)
}

func (s *ingressStoreStub) ObservePublicURLRecovery(
	ctx context.Context,
	identity controlstate.IngressLeaseIdentity,
	publicURLID string,
	publishRunNumber, recoveryEpisodeID uint64,
	observedAt time.Time,
) (controlstate.PublicURLRecoveryObservation, error) {
	return s.observeRecovery(ctx, identity, publicURLID, publishRunNumber, recoveryEpisodeID, observedAt)
}
