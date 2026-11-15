package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
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

func TestRetiredRoutingAndPolicyEndpointsAreNotServed(t *testing.T) {
	h := testIngressHandler(t, &ingressStoreStub{}, time.Now(), nil)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/internal/v1/ingresses/ingress-1/routing-table/snapshot"},
		{http.MethodGet, "/internal/v1/ingresses/ingress-1/routing-table/events"},
		{http.MethodPost, "/internal/v1/ingresses/ingress-1/visitor-policy"},
		{http.MethodPost, "/internal/v1/ingresses/ingress-1/public-url-recovery/9/observed"},
	} {
		t.Run(route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, authenticatedIngressRequest(route.method, route.path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatalf("retired endpoint = %d: %s", response.Code, response.Body.String())
			}
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
			Region: registration.Region,
			IngressLeaseIdentity: controlstate.IngressLeaseIdentity{
				IngressID: registration.IngressID, IngressRunID: registration.IngressRunID,
				IngressLeaseRevision: 7,
			},
			ProtocolVersion: registration.ProtocolVersion, ConnectionCapacity: registration.ConnectionCapacity,
			RegisteredAt: registeredAt, RenewedAt: registeredAt, LeaseExpiresAt: registeredAt.Add(leaseDuration),
		}, nil
	}}
	body := ingressv1.IngressRegistration{
		Region:    "aws:us-west-1",
		IngressId: "ingress-1", IngressRunId: "run-1", ProtocolVersion: 1, ConnectionCapacity: 100,
		IngressPoolId: "ingress-a", ServicePorts: []int{20000, 20001},
	}
	response := serveIngressJSON(
		t, testIngressHandler(t, store, now, nil), http.MethodPost,
		"/internal/v1/ingresses/register", body,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if string(got.Region) != body.Region || got.IngressID != body.IngressId || got.IngressRunID != body.IngressRunId ||
		got.ProtocolVersion != 1 || got.ConnectionCapacity != 100 || got.IngressPoolID != "ingress-a" || len(got.ServicePorts) != 2 || got.ServicePorts[1] != 20001 {
		t.Fatalf("registration = %#v", got)
	}
	if !gotNow.Equal(now) || gotDuration != 30*time.Second {
		t.Fatalf("register timing = %v, %v", gotNow, gotDuration)
	}
	var lease ingressv1.IngressLease
	decodeIngressResponse(t, response, &lease)
	if lease.Region != body.Region || lease.IngressId != "ingress-1" || lease.IngressLeaseRevision != 7 {
		t.Fatalf("lease = %#v", lease)
	}
}

func TestIngressRegistrationRequiresExplicitBoundedPortInventory(t *testing.T) {
	for _, test := range []struct {
		name  string
		ports []int
		pool  string
	}{
		{"missing ports", nil, "ingress-a"},
		{"missing pool", []int{20000}, ""},
		{"duplicate", []int{20000, 20000}, "ingress-a"},
		{"unsorted", []int{20001, 20000}, "ingress-a"},
		{"out of range", []int{65536}, "ingress-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := ingressv1.IngressRegistration{Region: "local", IngressId: "ingress-1", IngressRunId: "run-1", ProtocolVersion: 1, ConnectionCapacity: 100, IngressPoolId: test.pool, ServicePorts: test.ports}
			response := serveIngressJSON(t, testIngressHandler(t, &ingressStoreStub{}, time.Now(), nil), http.MethodPost, "/internal/v1/ingresses/register", body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("inventory status = %d", response.Code)
			}
		})
	}
}

func TestObserveServiceRecoveryUsesExactIngressLease(t *testing.T) {
	now := time.Now().UTC()
	ref := controlstate.ServiceRunReference{ServiceID: "svc_0123456789abcdefghijkl", RunID: "srun_0123456789abcdefghijkl", RunNumber: 3}
	const visitor = "vc_0123456789abcdefghijkl"
	var gotIdentity controlstate.IngressLeaseIdentity
	store := &ingressStoreStub{observeRecovery: func(
		_ context.Context,
		identity controlstate.IngressLeaseIdentity,
		run controlstate.ServiceRunReference,
		connection string,
		recoveryEpisodeID uint64,
		observedAt time.Time,
		evidence []byte,
		deliveredAt time.Time,
	) (controlstate.ServiceRecoveryObservation, error) {
		gotIdentity = identity
		if run != ref || connection != visitor || recoveryEpisodeID != 9 || !observedAt.Equal(now) || !deliveredAt.Equal(now) || !bytes.Equal(evidence, []byte("exact-source-evidence")) {
			t.Fatalf("recovery request = %+v, %q, %d, %v", run, connection, recoveryEpisodeID, observedAt)
		}
		return controlstate.ServiceRecoveryObservation{
			ServiceRunReference: run, RecoveryEpisodeID: recoveryEpisodeID,
			OpenedAt: now.Add(-time.Second), ObservedAt: now, ObservedSeconds: 1,
		}, nil
	}}
	body := ingressv1.ServiceRecoveryObservationRequest{
		IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7,
		ServiceId: ref.ServiceID, ServiceRunId: ref.RunID, RunNumber: ref.RunNumber, VisitorConnectionId: visitor, ObservedAt: now, SourceEvidence: []byte("exact-source-evidence"),
	}
	response := serveIngressJSON(
		t, testIngressHandler(t, store, now, nil), http.MethodPost,
		"/internal/v1/ingresses/ingress-1/service-recovery/9/observed", body,
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &ingressStoreStub{renewIngress: func(
				context.Context, controlstate.IngressRenewal, time.Time, time.Duration,
			) (controlstate.IngressLease, error) {
				return controlstate.IngressLease{}, test.err
			}}
			body := ingressv1.IngressRenewal{
				IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7,
			}
			response := serveIngressJSON(
				t, testIngressHandler(t, store, now, nil), http.MethodPost,
				"/internal/v1/ingresses/ingress-1/renew", body,
			)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			wire, err := ingressv1.ParseRenewIngressResponse(response.Result())
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RenewIngress(t.Context(), body.IngressId, body)
			var direct *serverhttp.ProblemError
			if !errors.As(err, &direct) || direct.Status != wire.StatusCode() || wire.ApplicationproblemJSONDefault == nil ||
				direct.Type != wire.ApplicationproblemJSONDefault.Type || direct.Title != wire.ApplicationproblemJSONDefault.Title ||
				direct.Detail != wire.ApplicationproblemJSONDefault.Detail {
				t.Fatalf("direct problem differs from HTTP: %#v, %v; HTTP %#v", direct, err, wire)
			}
			assertIngressProblemType(t, response, failureproblem.URL(test.problemType))
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

func testIngressSecrets(t *testing.T) serverhttp.BearerSecrets {
	t.Helper()
	secrets, err := serverhttp.NewBearerSecrets(testIngressClusterSecret, "")
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

type ingressStoreStub struct {
	publicServiceStore
	serviceAuditStore
	readIngressServices func(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressServices, error)
	registerIngress     func(context.Context, controlstate.IngressRegistration, time.Time, time.Duration) (controlstate.IngressLease, error)
	renewIngress        func(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error)
	beginIngressDrain   func(context.Context, controlstate.IngressLeaseIdentity, time.Time, time.Time) (controlstate.IngressLease, error)
	observeRecovery     func(context.Context, controlstate.IngressLeaseIdentity, controlstate.ServiceRunReference, string, uint64, time.Time, []byte, time.Time) (controlstate.ServiceRecoveryObservation, error)
}

func (s *ingressStoreStub) ReadIngressServices(ctx context.Context, identity controlstate.IngressLeaseIdentity, now time.Time) (controlstate.IngressServices, error) {
	return s.readIngressServices(ctx, identity, now)
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

func (s *ingressStoreStub) ObserveServiceRecovery(
	ctx context.Context,
	identity controlstate.IngressLeaseIdentity,
	run controlstate.ServiceRunReference,
	visitor string,
	recoveryEpisodeID uint64,
	observedAt time.Time,
	evidence []byte,
	now time.Time,
) (controlstate.ServiceRecoveryObservation, error) {
	return s.observeRecovery(ctx, identity, run, visitor, recoveryEpisodeID, observedAt, evidence, now)
}
