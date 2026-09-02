package routeclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestSignedClientBindsCoreRequestsAndRenewsHeartbeatAuthorization(t *testing.T) {
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	const routeID = "route_0123456789abcdef0123456789abcdef"
	var mu sync.Mutex
	var authorityRequests []authorityv1.IssueAuthorizationRequest
	var coreAuthorizations []string
	core := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/routes":
			var body serverv1.CreateRouteRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.AllowedIpPrefixes == nil || fmt.Sprint(*body.AllowedIpPrefixes) != "[192.0.2.0/24 2001:db8::/64]" {
				t.Errorf("create prefixes = %v", body.AllowedIpPrefixes)
			}
			mu.Lock()
			coreAuthorizations = append(coreAuthorizations, value(body.SignedAuthorization))
			mu.Unlock()
			_ = json.NewEncoder(response).Encode(setup(routeID, body.Hostname, 1, sessionToken))
		case "/v1/routes/" + routeID + "/sessions":
			var body serverv1.CreateRouteSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.AllowedIpPrefixes == nil || fmt.Sprint(*body.AllowedIpPrefixes) != "[192.0.2.0/24 2001:db8::/64]" {
				t.Errorf("session prefixes = %v", body.AllowedIpPrefixes)
			}
			mu.Lock()
			coreAuthorizations = append(coreAuthorizations, value(body.SignedAuthorization))
			mu.Unlock()
			_ = json.NewEncoder(response).Encode(setup(routeID, "demo.example", 2, sessionToken))
		case "/v1/routes/" + routeID + "/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+sessionToken.String() {
				t.Errorf("heartbeat Authorization = %q", request.Header.Get("Authorization"))
			}
			var body serverv1.HeartbeatRouteSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			coreAuthorizations = append(coreAuthorizations, value(body.SignedAuthorization))
			mu.Unlock()
			_ = json.NewEncoder(response).Encode(serverv1.HeartbeatResponse{ExpiresAt: time.Now().Add(time.Minute)})
		case "/v1/routes/" + routeID:
			if request.Method != http.MethodDelete || request.Header.Get("Authorization") != "Bearer "+routeToken.String() {
				t.Errorf("signed delete = %s, Authorization = %q", request.Method, request.Header.Get("Authorization"))
			}
			response.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(response, request)
		}
	}))
	defer core.Close()

	var authority *httptest.Server
	authority = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/authorizations" || request.Header.Get("Idempotency-Key") == "" {
			http.NotFound(response, request)
			return
		}
		var body authorityv1.IssueAuthorizationRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		authorityRequests = append(authorityRequests, body)
		index := len(authorityRequests)
		mu.Unlock()
		now := time.Now().Add(-time.Minute).UTC()
		authorizationID := fmt.Sprintf("authorization_%032x", index)
		retryID := fmt.Sprintf("retry_%032x", index)
		revision := 1
		if body.Operation == authorityv1.IssueAuthorizationRequestOperationAuthorizationRenew {
			now = time.Now().UTC()
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(authorityv1.AuthorizationEnvelope{
			Authorization: fmt.Sprintf("signed-%d", index),
			Claims: authorityv1.AuthorizationClaims{
				Version: authorityv1.N1, Kid: "key-1", Alg: authorityv1.AuthorizationClaimsAlgEdDSA,
				Operation: authorityv1.AuthorizationClaimsOperation(body.Operation), Issuer: authority.URL,
				Receiver: core.URL, AuthorizationId: authorizationID,
				Hostname: body.Hostname, RouteId: body.RouteId, RouteVersion: body.RouteVersion,
				Revision: revision, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
				RetryId: retryID, CanonicalRequestHash: body.CanonicalRequestHash,
				IpPolicyHash: body.IpPolicyHash,
			},
		})
	}))
	defer authority.Close()

	httpClient := core.Client()
	coreClient, err := serverclient.New(core.URL, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	authorityClient, err := authorityclient.New(authority.URL, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSigned(core.URL, coreClient, authorityClient, authorityv1.Capabilities{
		AuthorizationIssuer: authority.URL,
		AuthorizationKey:    authorityv1.AuthorizationKey{Kid: "key-1", Alg: authorityv1.AuthorizationKeyAlgEdDSA},
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := serverv1.AllowedIPPrefixes{"2001:db8::1/64", "192.0.2.42/24"}
	create := serverv1.CreateRouteRequest{
		Hostname: "demo.example", LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
		AllowedIpPrefixes: &allowed,
	}
	created, err := client.CreateRoute(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Heartbeat(context.Background(), routeID, 1, sessionToken); err != nil {
		t.Fatal(err)
	}
	created, err = client.CreateRouteSession(
		context.Background(), created.Route.Id, routeToken,
		[]string{"192.0.2.0/24", "2001:db8::/64"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Heartbeat(context.Background(), routeID, 2, sessionToken); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	route := client.routes[routeID]
	route.nextRenewal = time.Now().Add(-time.Second)
	client.routes[routeID] = route
	client.mu.Unlock()
	if _, err := client.Heartbeat(context.Background(), routeID, 2, sessionToken); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteRoute(context.Background(), routeID); err != nil {
		t.Fatal(err)
	}
	if routes, err := client.ListRoutes(context.Background()); err != nil || len(routes) != 0 {
		t.Fatalf("routes after signed delete = %#v, %v", routes, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(authorityRequests) != 3 {
		t.Fatalf("authority requests = %#v", authorityRequests)
	}
	wantCreateHash := hashLiteral(fmt.Sprintf(
		`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"hostname":"demo.example","local_target":"http://127.0.0.1:3000","route_token":%q}`,
		routeToken.String(),
	))
	wantSessionHash := hashLiteral(fmt.Sprintf(
		`{"allowed_ip_prefixes":["192.0.2.0/24","2001:db8::/64"],"route_token":%q}`,
		routeToken.String(),
	))
	wantHeartbeatHash := hashLiteral(`{"version":2}`)
	wantPolicyHash := hashLiteral(`["192.0.2.0/24","2001:db8::/64"]`)
	if authorityRequests[0].Operation != authorityv1.IssueAuthorizationRequestOperationRouteCreate ||
		authorityRequests[0].CanonicalRequestHash != wantCreateHash || value(authorityRequests[0].IpPolicyHash) != wantPolicyHash {
		t.Fatalf("route.create request = %#v", authorityRequests[0])
	}
	if authorityRequests[1].Operation != authorityv1.IssueAuthorizationRequestOperationRouteSessionCreate ||
		authorityRequests[1].CanonicalRequestHash != wantSessionHash || value(authorityRequests[1].RouteId) != routeID ||
		valueInt(authorityRequests[1].RouteVersion) != 2 || value(authorityRequests[1].IpPolicyHash) != wantPolicyHash {
		t.Fatalf("route_session.create request = %#v", authorityRequests[1])
	}
	if authorityRequests[2].Operation != authorityv1.IssueAuthorizationRequestOperationAuthorizationRenew ||
		authorityRequests[2].CanonicalRequestHash != wantHeartbeatHash || valueInt(authorityRequests[2].RouteVersion) != 2 ||
		value(authorityRequests[2].IpPolicyHash) != wantPolicyHash {
		t.Fatalf("authorization.renew request = %#v", authorityRequests[2])
	}
	wantAuthorizations := []string{"signed-1", "", "signed-2", "", "signed-3"}
	if fmt.Sprint(coreAuthorizations) != fmt.Sprint(wantAuthorizations) {
		t.Fatalf("Core authorizations = %v, want %v", coreAuthorizations, wantAuthorizations)
	}
}

func TestCanonicalPrefixesPreserveExplicitEmptyPolicy(t *testing.T) {
	empty := serverv1.AllowedIPPrefixes{}
	canonical, err := canonicalizeIPPrefixes(&empty)
	if err != nil {
		t.Fatal(err)
	}
	if canonical == nil || *canonical == nil || len(*canonical) != 0 {
		t.Fatalf("canonical empty policy = %#v", canonical)
	}
	cloned := clonePrefixes(canonical)
	if cloned == nil || *cloned == nil || len(*cloned) != 0 {
		t.Fatalf("cloned empty policy = %#v", cloned)
	}
	digest, err := ipPolicyHash(cloned)
	if err != nil {
		t.Fatal(err)
	}
	want := authorityv1.SHA256Digest(hashLiteral("[]"))
	if digest == nil || *digest != want {
		t.Fatalf("empty policy hash = %v, want %q", digest, want)
	}
	if missing, err := canonicalizeIPPrefixes(nil); err != nil || missing != nil {
		t.Fatalf("omitted policy = %#v, %v", missing, err)
	}
}

func TestSignedClientPreservesIdempotencyAcrossAmbiguousFailures(t *testing.T) {
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	const routeID = "route_0123456789abcdef0123456789abcdef"
	var mu sync.Mutex
	authorityKeys := make(map[string][]string)
	authorityAttempts := make(map[string]int)
	coreAuthorizations := make(map[string][]string)
	coreAttempts := make(map[string]int)

	core := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		operation := ""
		authorization := ""
		switch request.URL.Path {
		case "/v1/routes":
			operation = "route.create"
			var body serverv1.CreateRouteRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			authorization = value(body.SignedAuthorization)
		case "/v1/routes/" + routeID + "/sessions":
			operation = "route_session.create"
			var body serverv1.CreateRouteSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			authorization = value(body.SignedAuthorization)
		case "/v1/routes/" + routeID + "/heartbeat":
			operation = "authorization.renew"
			var body serverv1.HeartbeatRouteSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			authorization = value(body.SignedAuthorization)
		default:
			http.NotFound(response, request)
			return
		}
		mu.Lock()
		coreAttempts[operation]++
		attempt := coreAttempts[operation]
		coreAuthorizations[operation] = append(coreAuthorizations[operation], authorization)
		mu.Unlock()
		if attempt == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(serverv1.Problem{
				Code: serverv1.TemporarilyUnavailable, Details: map[string]any{}, RequestId: "request_retry",
				Status: http.StatusServiceUnavailable, Title: "Temporarily unavailable", Type: "about:blank",
			})
			return
		}
		switch operation {
		case "route.create":
			_ = json.NewEncoder(response).Encode(setup(routeID, "retry.example", 1, sessionToken))
		case "route_session.create":
			_ = json.NewEncoder(response).Encode(setup(routeID, "retry.example", 2, sessionToken))
		case "authorization.renew":
			_ = json.NewEncoder(response).Encode(serverv1.HeartbeatResponse{ExpiresAt: time.Now().Add(time.Minute)})
		}
	}))
	defer core.Close()

	var authority *httptest.Server
	authority = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body authorityv1.IssueAuthorizationRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		operation := string(body.Operation)
		mu.Lock()
		authorityAttempts[operation]++
		attempt := authorityAttempts[operation]
		authorityKeys[operation] = append(authorityKeys[operation], request.Header.Get("Idempotency-Key"))
		mu.Unlock()
		if attempt == 1 {
			http.Error(response, "ambiguous", http.StatusServiceUnavailable)
			return
		}
		sequence := map[string]int{
			"route.create": 1, "route_session.create": 2, "authorization.renew": 3,
		}[operation]
		issuedAt := time.Now().Add(-time.Minute).UTC()
		if operation == "authorization.renew" {
			issuedAt = time.Now().UTC()
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(authorityv1.AuthorizationEnvelope{
			Authorization: fmt.Sprintf("signed-retry-%d", sequence),
			Claims: authorityv1.AuthorizationClaims{
				Version: authorityv1.N1, Kid: "key-1", Alg: authorityv1.AuthorizationClaimsAlgEdDSA,
				Operation: authorityv1.AuthorizationClaimsOperation(body.Operation), Issuer: authority.URL,
				Receiver: core.URL, AuthorizationId: fmt.Sprintf("authorization_%032x", sequence),
				Hostname: body.Hostname, RouteId: body.RouteId, RouteVersion: body.RouteVersion,
				Revision: 1, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
				RetryId: fmt.Sprintf("retry_%032x", sequence), CanonicalRequestHash: body.CanonicalRequestHash,
				IpPolicyHash: body.IpPolicyHash,
			},
		})
	}))
	defer authority.Close()

	httpClient := core.Client()
	coreClient, err := serverclient.New(core.URL, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	authorityClient, err := authorityclient.New(authority.URL, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSigned(core.URL, coreClient, authorityClient, authorityv1.Capabilities{
		AuthorizationIssuer: authority.URL,
		AuthorizationKey:    authorityv1.AuthorizationKey{Kid: "key-1", Alg: authorityv1.AuthorizationKeyAlgEdDSA},
	})
	if err != nil {
		t.Fatal(err)
	}
	create := serverv1.CreateRouteRequest{
		Hostname: "retry.example", LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	}
	if _, err := client.CreateRoute(t.Context(), create); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("authority create failure = %v", err)
	}
	if _, err := client.CreateRoute(t.Context(), create); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("Core create failure = %v", err)
	}
	if _, err := client.CreateRoute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRouteSession(t.Context(), routeID, routeToken, nil); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("authority session failure = %v", err)
	}
	if _, err := client.CreateRouteSession(t.Context(), routeID, routeToken, nil); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("Core session failure = %v", err)
	}
	if _, err := client.CreateRouteSession(t.Context(), routeID, routeToken, nil); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	route := client.routes[routeID]
	route.nextRenewal = time.Now().Add(-time.Second)
	client.routes[routeID] = route
	client.mu.Unlock()
	if _, err := client.Heartbeat(t.Context(), routeID, 2, sessionToken); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("authority renewal failure = %v", err)
	}
	if _, err := client.Heartbeat(t.Context(), routeID, 2, sessionToken); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("Core renewal failure = %v", err)
	}
	if _, err := client.Heartbeat(t.Context(), routeID, 2, sessionToken); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, operation := range []string{"route.create", "route_session.create", "authorization.renew"} {
		keys := authorityKeys[operation]
		if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
			t.Errorf("%s authority keys = %#v", operation, keys)
		}
		authorizations := coreAuthorizations[operation]
		if len(authorizations) != 2 || authorizations[0] == "" || authorizations[0] != authorizations[1] {
			t.Errorf("%s Core authorizations = %#v", operation, authorizations)
		}
	}
}

func setup(routeID, hostname string, version int, sessionToken credentials.SessionToken) serverv1.SessionSetup {
	return serverv1.SessionSetup{
		Route: serverv1.Route{
			Id: routeID, Hostname: hostname, LocalTarget: "http://127.0.0.1:3000", Version: version,
		},
		Session:      serverv1.RouteSession{RouteId: routeID, Version: version},
		SessionToken: sessionToken.String(), WorkerPublicKey: "nodekey:" + fmt.Sprintf("%064x", 1),
	}
}

func hashLiteral(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

func valueInt(pointer *int) int {
	if pointer == nil {
		return 0
	}
	return *pointer
}
