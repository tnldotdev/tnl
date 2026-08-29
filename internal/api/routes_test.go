package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/routes"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"tailscale.com/types/key"
)

func TestRouteAPILifecycle(t *testing.T) {
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(db, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := authService.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db)
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

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created := routeRequest[corev1.LeaseSetup](t, handler, issued.Token.String(), http.MethodPost, routesPath, corev1.CreateRouteRequest{
		Hostname: "route.example", DisplayTarget: "localhost:3000", RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if created.Route.Generation != 1 || created.Lease.Generation != 1 {
		t.Fatalf("created setup = %#v", created)
	}
	serverKey := key.NewNode().Public().String()
	routeRequest[struct{}](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/transport", corev1.RegisterTransportRequest{
		Generation: 1,
		Endpoint: corev1.TailcatDescriptor{
			Version: corev1.TailcatDescriptorVersionN1, ServerPublicKey: serverKey, RelayProfile: "default",
		},
	}, http.StatusNoContent)
	routeRequest[struct{}](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/ready", corev1.LeaseGenerationRequest{Generation: 1}, http.StatusNoContent)
	heartbeat := routeRequest[corev1.HeartbeatResponse](t, handler, created.LeaseToken, http.MethodPost, routesPath+"/"+created.Route.Id+"/heartbeat", corev1.LeaseGenerationRequest{Generation: 1}, http.StatusOK)
	if heartbeat.ExpiresAt.IsZero() {
		t.Fatal("heartbeat omitted expiry")
	}
	listed := routeRequest[[]corev1.Route](t, handler, issued.Token.String(), http.MethodGet, routesPath, nil, http.StatusOK)
	if len(listed) != 1 || listed[0].Id != created.Route.Id {
		t.Fatalf("listed routes = %#v", listed)
	}
	replacement := routeRequest[corev1.LeaseSetup](t, handler, issued.Token.String(), http.MethodPost, routesPath+"/"+created.Route.Id+"/leases", corev1.AcquireLeaseRequest{
		RouteToken: routeToken.String(),
	}, http.StatusCreated)
	if replacement.Lease.Generation != 2 {
		t.Fatalf("replacement setup = %#v", replacement)
	}
	routeRequest[struct{}](t, handler, issued.Token.String(), http.MethodDelete, routesPath+"/"+created.Route.Id, nil, http.StatusNoContent)
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
