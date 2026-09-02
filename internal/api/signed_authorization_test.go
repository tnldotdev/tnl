package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestSignedRouteAPIBypassesCoreIdentityAndRetriesExactly(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authorization.NewVerifier(authorization.Config{
		Issuer: "https://authority.example", Receiver: "https://core.example", KeyID: "key-1",
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := routes.NewStore(db, "example", routes.StoreConfig{AuthorizationVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(ctx, store, "instance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	handler := NewHandlerWithServicesAndConfig(
		fixtureCapabilities(t), nil, coordinator, nil, HandlerConfig{SignedAuthorization: true},
	)
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	request := serverv1.CreateRouteRequest{
		Hostname: "route.example", LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	}
	requestHash, err := authorization.CanonicalRequestHash(authorization.CoreRequest{
		Operation: authorization.OperationRouteCreate, Hostname: request.Hostname,
		LocalTarget: request.LocalTarget, RouteToken: request.RouteToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := apiSignedClaims{
		Version: 1, KeyID: "key-1", Algorithm: authorization.Algorithm,
		Operation: authorization.OperationRouteCreate, Issuer: "https://authority.example", Receiver: "https://core.example",
		AuthorizationID: "authorization_00000000000000000000000000000001", Hostname: request.Hostname,
		Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		RetryID: "retry_00000000000000000000000000000001", CanonicalRequestHash: requestHash.String(),
	}
	signed := signAPIAuthorization(t, privateKey, claims)
	request.SignedAuthorization = &signed
	created := routeRequest[serverv1.SessionSetup](
		t, handler, "", http.MethodPost, routesPath, request, http.StatusCreated,
	)
	replayed := routeRequest[serverv1.SessionSetup](
		t, handler, "", http.MethodPost, routesPath, request, http.StatusCreated,
	)
	if replayed.Route.Id != created.Route.Id || replayed.Session.Id != created.Session.Id ||
		replayed.SessionToken != created.SessionToken || replayed.WorkerPublicKey != created.WorkerPublicKey {
		t.Fatalf("replayed setup = %#v, created = %#v", replayed, created)
	}
	wrongRouteToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	deletePath := routesPath + "/" + created.Route.Id
	routeRequest[serverv1.Problem](t, handler, "", http.MethodDelete, deletePath, nil, http.StatusUnauthorized)
	routeRequest[serverv1.Problem](t, handler, wrongRouteToken.String(), http.MethodDelete, deletePath, nil, http.StatusUnauthorized)
	routeRequest[struct{}](t, handler, routeToken.String(), http.MethodDelete, deletePath, nil, http.StatusNoContent)
	routeRequest[serverv1.Problem](t, handler, routeToken.String(), http.MethodDelete, deletePath, nil, http.StatusUnauthorized)
	request.SignedAuthorization = nil
	routeRequest[serverv1.Problem](t, handler, "", http.MethodPost, routesPath, request, http.StatusBadRequest)
}

func TestClientIPUsesRemoteAddressAndDedicatedLimit(t *testing.T) {
	handler := NewHandlerWithServicesAndConfig(fixtureCapabilities(t), nil, nil, nil, HandlerConfig{}).(*handler)
	handler.clientIPLimit = testAPISourceLimiter(t)

	request := httptest.NewRequest(http.MethodGet, clientIPPath, nil)
	request.RemoteAddr = "[::ffff:192.0.2.10]:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var body serverv1.ClientIPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Ip != "192.0.2.10" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %#v, %v", body, err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("limited status = %d, retry-after = %q", response.Code, response.Header().Get("Retry-After"))
	}
	request = httptest.NewRequest(http.MethodGet, clientIPPath, nil)
	request.RemoteAddr = "192.0.2.11:4321"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("independent source status = %d: %s", response.Code, response.Body.String())
	}

	malformed := NewHandlerWithServicesAndConfig(fixtureCapabilities(t), nil, nil, nil, HandlerConfig{})
	request = httptest.NewRequest(http.MethodGet, clientIPPath, nil)
	request.RemoteAddr = "invalid"
	response = httptest.NewRecorder()
	malformed.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed remote status = %d: %s", response.Code, response.Body.String())
	}
}

type apiSignedClaims struct {
	Version              uint64                  `json:"version"`
	KeyID                string                  `json:"kid"`
	Algorithm            string                  `json:"alg"`
	Operation            authorization.Operation `json:"operation"`
	Issuer               string                  `json:"issuer"`
	Receiver             string                  `json:"receiver"`
	AuthorizationID      string                  `json:"authorization_id"`
	Hostname             string                  `json:"hostname"`
	RouteID              *string                 `json:"route_id,omitempty"`
	RouteVersion         *uint64                 `json:"route_version,omitempty"`
	Revision             uint64                  `json:"revision"`
	IssuedAt             time.Time               `json:"issued_at"`
	ExpiresAt            time.Time               `json:"expires_at"`
	RetryID              string                  `json:"retry_id"`
	CanonicalRequestHash string                  `json:"canonical_request_hash"`
	IPPolicyHash         *string                 `json:"ip_policy_hash,omitempty"`
}

func signAPIAuthorization(t *testing.T, privateKey ed25519.PrivateKey, claims apiSignedClaims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": authorization.Algorithm, "kid": claims.KeyID, "typ": authorization.Type,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var signingInput bytes.Buffer
	signingInput.WriteString(base64.RawURLEncoding.EncodeToString(header))
	signingInput.WriteByte('.')
	signingInput.WriteString(base64.RawURLEncoding.EncodeToString(payload))
	signature := ed25519.Sign(privateKey, signingInput.Bytes())
	return signingInput.String() + "." + base64.RawURLEncoding.EncodeToString(signature)
}
