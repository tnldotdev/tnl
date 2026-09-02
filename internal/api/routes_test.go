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
	authService, err := auth.NewService(db, auth.ServiceConfig{
		LoginToken: login, LoginTokenRevision: 1,
		AccessLifetime: auth.DefaultAccessTokenLifetime, RefreshLifetime: auth.DefaultRefreshTokenLifetime,
	})
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
	coordinator, err := routes.NewCoordinator(context.Background(), store, "instance")
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AddWorker("local", apiRouteWorker{}); err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithRoutes(fixtureCapabilities(t), authService, coordinator)
	addHostnameRequest(t, handler, issued.AccessToken.String(), "route")

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created := routeRequest[serverv1.SessionSetup](t, handler, issued.AccessToken.String(), http.MethodPost, routesPath, serverv1.CreateRouteRequest{
		Hostname: "route.example", LocalTarget: "localhost:3000", RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if created.Route.Version != 1 || created.Session.Version != 1 {
		t.Fatalf("created setup = %#v", created)
	}
	serverKey := key.NewNode().Public().String()
	routeRequest[struct{}](t, handler, created.SessionToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/transport", serverv1.RegisterTransportRequest{
		Version: 1,
		Endpoint: serverv1.TailcatDescriptor{
			Version: serverv1.TailcatDescriptorVersionN1, PublisherPublicKey: serverKey, RelayRegion: "default",
		},
	}, http.StatusNoContent)
	routeRequest[struct{}](t, handler, created.SessionToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/ready", serverv1.RouteVersionRequest{Version: 1}, http.StatusNoContent)
	heartbeat := routeRequest[serverv1.HeartbeatResponse](t, handler, created.SessionToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/heartbeat", serverv1.HeartbeatRouteSessionRequest{Version: 1}, http.StatusOK)
	if heartbeat.ExpiresAt.IsZero() {
		t.Fatal("heartbeat omitted expiry")
	}
	listed := routeRequest[[]serverv1.Route](t, handler, issued.AccessToken.String(), http.MethodGet, routesPath, nil, http.StatusOK)
	if len(listed) != 1 || listed[0].Id != created.Route.Id {
		t.Fatalf("listed routes = %#v", listed)
	}
	replacement := routeRequest[serverv1.SessionSetup](t, handler, issued.AccessToken.String(), http.MethodPost, routesPath+"/"+created.Route.Id+"/sessions", serverv1.CreateRouteSessionRequest{
		RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if replacement.Session.Version != 2 {
		t.Fatalf("replacement setup = %#v", replacement)
	}
	routeRequest[struct{}](t, handler, issued.AccessToken.String(), http.MethodDelete, routesPath+"/"+created.Route.Id, nil, http.StatusNoContent)
}

func TestRouteAllowedIPPrefixesPreservesExplicitEmptyPolicy(t *testing.T) {
	empty := serverv1.AllowedIPPrefixes{}
	prefixes, err := routeAllowedIPPrefixes(&empty)
	if err != nil {
		t.Fatal(err)
	}
	if prefixes == nil || len(prefixes) != 0 {
		t.Fatalf("explicit empty policy = %#v", prefixes)
	}
	missing, err := routeAllowedIPPrefixes(nil)
	if err != nil || missing != nil {
		t.Fatalf("omitted policy = %#v, %v", missing, err)
	}
}

func TestHostnameListAndRemove(t *testing.T) {
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
	authService, err := auth.NewService(db, auth.ServiceConfig{
		LoginToken: login, LoginTokenRevision: 1,
		AccessLifetime: auth.DefaultAccessTokenLifetime, RefreshLifetime: auth.DefaultRefreshTokenLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authService.Exchange(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authService.Authenticate(ctx, issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	const customID = "hostname_00000000000000000000000000000001"
	const managedID = "hostname_00000000000000000000000000000002"
	if _, err := db.ExecContext(ctx, `INSERT INTO hostnames
		(id, identity_id, hostname, created_at, kind, status, source, activated_at)
		VALUES
		(?, ?, 'docs.other.com', 1, 'custom_domain', 'active', 'user', 1),
		(?, ?, 'managed.example', 1, 'managed', 'active', 'user', 1)`,
		customID, principal.Identity.ID, managedID, principal.Identity.ID); err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(ctx, store, "instance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	handler := NewHandlerWithRoutes(fixtureCapabilities(t), authService, coordinator)
	listed := routeRequest[serverv1.HostnamePage](
		t, handler, issued.AccessToken.String(), http.MethodGet, hostnamesPath, nil, http.StatusOK,
	)
	if len(listed.Hostnames) != 2 || listed.Hostnames[0].Id != customID || listed.Hostnames[1].Id != managedID {
		t.Fatalf("hostnames = %#v", listed)
	}
	routeRequest[struct{}](
		t, handler, issued.AccessToken.String(), http.MethodDelete, hostnamesPath+"/"+customID, nil, http.StatusNoContent,
	)
	listed = routeRequest[serverv1.HostnamePage](
		t, handler, issued.AccessToken.String(), http.MethodGet, hostnamesPath, nil, http.StatusOK,
	)
	if len(listed.Hostnames) != 1 || listed.Hostnames[0].Id != managedID || listed.Hostnames[0].Status != serverv1.HostnameStatusActive {
		t.Fatalf("hostnames after custom-domain removal = %#v", listed)
	}
	routeRequest[struct{}](
		t, handler, issued.AccessToken.String(), http.MethodDelete, hostnamesPath+"/"+managedID, nil, http.StatusNoContent,
	)
	listed = routeRequest[serverv1.HostnamePage](
		t, handler, issued.AccessToken.String(), http.MethodGet, hostnamesPath, nil, http.StatusOK,
	)
	if len(listed.Hostnames) != 1 || listed.Hostnames[0].Id != managedID || listed.Hostnames[0].Status != serverv1.HostnameStatusInactive {
		t.Fatalf("hostnames after managed removal = %#v", listed)
	}
}

func TestCertificateAPIRequiresBoundCurrentSession(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(db, auth.ServiceConfig{
		LoginToken: login, LoginTokenRevision: 1,
		AccessLifetime: auth.DefaultAccessTokenLifetime, RefreshLifetime: auth.DefaultRefreshTokenLifetime,
	})
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
	coordinator, err := routes.NewCoordinator(context.Background(), store, "instance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	certificates := &apiCertificateService{}
	handler := NewHandlerWithServices(fixtureCapabilities(t), authService, coordinator, certificates)
	addHostnameRequest(t, handler, issued.AccessToken.String(), "route")
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created := routeRequest[serverv1.SessionSetup](t, handler, issued.AccessToken.String(), http.MethodPost, routesPath, serverv1.CreateRouteRequest{
		Hostname: "route.example", LocalTarget: "localhost:3000", RouteToken: routeToken.String(),
	}, http.StatusCreated)
	request := serverv1.CreateCertificateIssuanceRequest{
		RouteId: created.Route.Id, Version: 1, AcmeProfile: "tlsserver",
		Csr: base64.RawURLEncoding.EncodeToString([]byte("csr")),
	}
	issuance := routeRequest[serverv1.CertificateIssuance](
		t, handler, created.SessionToken, http.MethodPost, certificateIssuancesPath, request, http.StatusCreated,
	)
	if issuance.RouteId != created.Route.Id || issuance.Status != serverv1.CertificateIssuanceStatusWaitingForChallenge || issuance.Challenge == nil {
		t.Fatalf("certificate issuance = %#v", issuance)
	}
	wrongToken, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	routeRequest[serverv1.Problem](
		t, handler, wrongToken.String(), http.MethodGet, certificateIssuancesPath+"/"+issuance.Id, nil, http.StatusUnauthorized,
	)
	advanced := routeRequest[serverv1.CertificateIssuance](
		t, handler, created.SessionToken, http.MethodPost,
		certificateIssuancesPath+"/"+issuance.Id+"/challenge-ready", nil, http.StatusOK,
	)
	if advanced.Status != serverv1.CertificateIssuanceStatusWaitingForInstall || advanced.CertificatePem == nil {
		t.Fatalf("advanced issuance = %#v", advanced)
	}
	routeRequest[struct{}](
		t, handler, created.SessionToken, http.MethodPost,
		certificateIssuancesPath+"/"+issuance.Id+"/challenge-removed", nil, http.StatusNoContent,
	)
	routeRequest[struct{}](
		t, handler, created.SessionToken, http.MethodPost,
		routesPath+"/"+created.Route.Id+"/certificate-installed",
		serverv1.CertificateInstalledRequest{Version: 1, IssuanceId: issuance.Id}, http.StatusNoContent,
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

func addHostnameRequest(t *testing.T, handler http.Handler, token, label string) serverv1.Hostname {
	t.Helper()
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(serverv1.AddHostnameRequest{
		Kind: serverv1.AddHostnameRequestKindManaged, Name: &label,
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, hostnamesPath, &body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "api-route-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("hostname status = %d, body = %s", response.Code, response.Body.String())
	}
	var hostname serverv1.Hostname
	if err := json.NewDecoder(response.Body).Decode(&hostname); err != nil {
		t.Fatal(err)
	}
	return hostname
}

type apiRouteWorker struct{}

func (apiRouteWorker) Attach(context.Context, worker.Assignment) (worker.WorkerRoute, error) {
	return apiWorkerRoute{}, nil
}

func (apiRouteWorker) Capacity() worker.Capacity   { return worker.Capacity{Limit: 10} }
func (apiRouteWorker) Drain(context.Context) error { return nil }
func (apiRouteWorker) Close() error                { return nil }

type apiWorkerRoute struct{}

func (apiWorkerRoute) Open(context.Context) (net.Conn, error) {
	local, peer := net.Pipe()
	_ = peer.Close()
	return local, nil
}
func (apiWorkerRoute) Drain(context.Context) error { return nil }
func (apiWorkerRoute) Close() error                { return nil }

type apiCertificateService struct{ issuance certificates.Issuance }

func (s *apiCertificateService) Create(
	_ context.Context,
	routeID string,
	version uint64,
	profile string,
	_ []byte,
) (certificates.Issuance, error) {
	now := time.Now().UTC()
	s.issuance = certificates.Issuance{
		ID: "issuance_0123456789abcdef0123456789abcdef", RouteID: routeID, Version: version,
		Hostname: "route.example", ACMEProfile: profile, Status: certificates.StatusWaitingChallenge,
		ChallengeURL: "challenge", ChallengeExpires: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	return s.issuance, nil
}

func (s *apiCertificateService) Get(context.Context, string) (certificates.Issuance, error) {
	return s.issuance, nil
}

func (s *apiCertificateService) ChallengeReady(context.Context, string) (certificates.Issuance, error) {
	s.issuance.Status = certificates.StatusWaitingForInstall
	s.issuance.CertificatePEM = []byte("certificate")
	return s.issuance, nil
}

func (s *apiCertificateService) ChallengeRemoved(context.Context, string) (certificates.Issuance, error) {
	s.issuance.ChallengeRemoved = time.Now().UTC()
	return s.issuance, nil
}

func (s *apiCertificateService) Installed(
	_ context.Context,
	_, routeID string,
	version uint64,
) (certificates.Issuance, error) {
	if routeID != s.issuance.RouteID || version != s.issuance.Version || s.issuance.ChallengeRemoved.IsZero() {
		return certificates.Issuance{}, certificates.ErrInvalidStatus
	}
	s.issuance.Status = certificates.StatusInstalled
	return s.issuance, nil
}
