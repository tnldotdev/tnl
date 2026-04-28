package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"tailscale.com/types/key"
)

func TestRouteAPILifecycle(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(db, login)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authService.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(context.Background(), store, "boot")
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AddOwner("local", apiRouteOwner{}); err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithRoutes(fixtureCapabilities(t), authService, coordinator)
	claimRequest(t, handler, issued.Token.String(), "route")

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created := routeRequest[serverv1.LeaseSetup](t, handler, issued.Token.String(), http.MethodPost, routesPath, serverv1.CreateRouteRequest{
		Hostname: "route.example", DisplayTarget: "localhost:3000", RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if created.Route.Generation != 1 || created.Lease.Generation != 1 {
		t.Fatalf("created setup = %#v", created)
	}
	serverKey := key.NewNode().Public().String()
	routeRequest[struct{}](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/transport", serverv1.RegisterTransportRequest{
		Generation: 1,
		Endpoint: serverv1.TailcatDescriptor{
			Version: serverv1.TailcatDescriptorVersionN1, ServerPublicKey: serverKey, RelayProfile: "default",
		},
	}, http.StatusNoContent)
	routeRequest[struct{}](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/ready", serverv1.LeaseGenerationRequest{Generation: 1}, http.StatusNoContent)
	heartbeat := routeRequest[serverv1.HeartbeatResponse](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/heartbeat", serverv1.LeaseGenerationRequest{Generation: 1}, http.StatusOK)
	if heartbeat.ExpiresAt.IsZero() {
		t.Fatal("heartbeat omitted expiry")
	}
	listed := routeRequest[[]serverv1.Route](t, handler, issued.Token.String(), http.MethodGet, routesPath, nil, http.StatusOK)
	if len(listed) != 1 || listed[0].Id != created.Route.Id {
		t.Fatalf("listed routes = %#v", listed)
	}
	replacement := routeRequest[serverv1.LeaseSetup](t, handler, issued.Token.String(), http.MethodPost, routesPath+"/"+created.Route.Id+"/leases", serverv1.AcquireLeaseRequest{
		RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if replacement.Lease.Generation != 2 {
		t.Fatalf("replacement setup = %#v", replacement)
	}
	routeRequest[struct{}](t, handler, issued.Token.String(), http.MethodDelete, routesPath+"/"+created.Route.Id, nil, http.StatusNoContent)
}

func TestDomainClaimListAndRelease(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(db, login)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authService.Exchange(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authService.Authenticate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	const claimID = "claim_00000000000000000000000000000001"
	const managedID = "claim_00000000000000000000000000000002"
	if _, err := db.ExecContext(ctx, `INSERT INTO hostname_claims
		(id, principal_id, hostname, created_at, kind, state, source, activated_at)
		VALUES
		(?, ?, 'docs.other.com', 1, 'persistent_custom_domain', 'active', 'custom', 1),
		(?, ?, 'managed.example', 1, 'persistent_managed', 'active', 'custom', 1)`,
		claimID, principal.ID, managedID, principal.ID); err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(ctx, store, "boot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	handler := NewHandlerWithRoutes(fixtureCapabilities(t), authService, coordinator)
	listed := routeRequest[[]serverv1.HostnameClaim](
		t, handler, issued.Token.String(), http.MethodGet, domainClaimsPath, nil, http.StatusOK,
	)
	if len(listed) != 1 || listed[0].Id != claimID {
		t.Fatalf("domain claims = %#v", listed)
	}
	routeRequest[serverv1.Problem](
		t, handler, issued.Token.String(), http.MethodDelete, domainClaimsPath+"/"+managedID, nil, http.StatusNotFound,
	)
	routeRequest[struct{}](
		t, handler, issued.Token.String(), http.MethodDelete, domainClaimsPath+"/"+claimID, nil, http.StatusNoContent,
	)
	listed = routeRequest[[]serverv1.HostnameClaim](
		t, handler, issued.Token.String(), http.MethodGet, domainClaimsPath, nil, http.StatusOK,
	)
	if len(listed) != 0 {
		t.Fatalf("released domain claims = %#v", listed)
	}
}

func TestCertificateAPIRequiresBoundCurrentLease(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(db, login)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authService.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(context.Background(), store, "boot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	certificates := &apiCertificateService{}
	handler := NewHandlerWithServices(fixtureCapabilities(t), authService, coordinator, certificates)
	claimRequest(t, handler, issued.Token.String(), "route")
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created := routeRequest[serverv1.LeaseSetup](t, handler, issued.Token.String(), http.MethodPost, routesPath, serverv1.CreateRouteRequest{
		Hostname: "route.example", DisplayTarget: "localhost:3000", RouteToken: routeToken.String(),
	}, http.StatusCreated)
	request := serverv1.CreateCertificateOrderRequest{
		RouteId: created.Route.Id, Generation: 1, Profile: "tlsserver",
		Csr: base64.RawURLEncoding.EncodeToString([]byte("csr")),
	}
	order := routeRequest[serverv1.CertificateOrder](
		t, handler, created.LeaseToken, http.MethodPost, certificateOrdersPath, request, http.StatusCreated,
	)
	if order.RouteId != created.Route.Id || order.State != serverv1.WaitingForChallenge || order.Challenge == nil {
		t.Fatalf("certificate order = %#v", order)
	}
	wrongToken, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	routeRequest[serverv1.Problem](
		t, handler, wrongToken.String(), http.MethodGet, certificateOrdersPath+"/"+order.Id, nil, http.StatusUnauthorized,
	)
	advanced := routeRequest[serverv1.CertificateOrder](
		t, handler, created.LeaseToken, http.MethodPost,
		certificateOrdersPath+"/"+order.Id+"/challenge-ready", nil, http.StatusOK,
	)
	if advanced.State != serverv1.WaitingForInstall || advanced.CertificatePem == nil {
		t.Fatalf("advanced order = %#v", advanced)
	}
	routeRequest[struct{}](
		t, handler, created.LeaseToken, http.MethodPost,
		certificateOrdersPath+"/"+order.Id+"/challenge-removed", nil, http.StatusNoContent,
	)
	routeRequest[struct{}](
		t, handler, created.LeaseToken, http.MethodPost,
		routesPath+"/"+created.Route.Id+"/certificate-installed",
		serverv1.CertificateInstalledRequest{Generation: 1, OrderId: order.Id}, http.StatusNoContent,
	)
}

func routeRequest[T any](
	t *testing.T,
	handler http.Handler,
	token, method, path string,
	requestBody any,
	wantStatus int,
) T {
	t.Helper()
	var body bytes.Buffer
	if requestBody != nil {
		if err := json.NewEncoder(&body).Encode(requestBody); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &body)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set(authorizationHeader, "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d: %s", method, path, response.Code, wantStatus, response.Body.String())
	}
	var result T
	if response.Body.Len() != 0 {
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func claimRequest(t *testing.T, handler http.Handler, token, label string) serverv1.HostnameClaim {
	t.Helper()
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(serverv1.CreateHostnameClaimRequest{
		Kind: serverv1.CreateHostnameClaimRequestKindPersistentManaged, Name: &label,
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, hostnameClaimsPath, &body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "api-route-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, body = %s", response.Code, response.Body.String())
	}
	var claim serverv1.HostnameClaim
	if err := json.NewDecoder(response.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	return claim
}

type apiRouteOwner struct{}

func (apiRouteOwner) Attach(context.Context, worker.Assignment) (worker.OwnedRoute, error) {
	return apiOwnedRoute{}, nil
}

func (apiRouteOwner) Capacity() worker.Capacity   { return worker.Capacity{Limit: 10} }
func (apiRouteOwner) Drain(context.Context) error { return nil }
func (apiRouteOwner) Close() error                { return nil }

type apiOwnedRoute struct{}

func (apiOwnedRoute) Open(context.Context) (net.Conn, error) {
	local, peer := net.Pipe()
	_ = peer.Close()
	return local, nil
}
func (apiOwnedRoute) Drain(context.Context) error { return nil }
func (apiOwnedRoute) Close() error                { return nil }

type apiCertificateService struct{ job certificates.Job }

func (s *apiCertificateService) Create(
	_ context.Context,
	routeID string,
	generation uint64,
	profile string,
	_ []byte,
) (certificates.Job, error) {
	now := time.Now().UTC()
	s.job = certificates.Job{
		ID: "cert_0123456789abcdef0123456789abcdef", RouteID: routeID, Generation: generation,
		Hostname: "route.example", Profile: profile, State: certificates.StateWaitingChallenge,
		ChallengeURL: "challenge", ChallengeExpires: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	return s.job, nil
}

func (s *apiCertificateService) Get(context.Context, string) (certificates.Job, error) {
	return s.job, nil
}

func (s *apiCertificateService) ChallengeReady(context.Context, string) (certificates.Job, error) {
	s.job.State = certificates.StateWaitingForInstall
	s.job.CertificatePEM = []byte("certificate")
	return s.job, nil
}

func (s *apiCertificateService) ChallengeRemoved(context.Context, string) (certificates.Job, error) {
	s.job.ChallengeRemoved = time.Now().UTC()
	return s.job, nil
}

func (s *apiCertificateService) Installed(
	_ context.Context,
	_, routeID string,
	generation uint64,
) (certificates.Job, error) {
	if routeID != s.job.RouteID || generation != s.job.Generation || s.job.ChallengeRemoved.IsZero() {
		return certificates.Job{}, certificates.ErrInvalidState
	}
	s.job.State = certificates.StateSucceeded
	return s.job, nil
}
