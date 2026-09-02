package clientauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestClientRetriesOneUnauthorizedRequestAfterSerializedRefresh(t *testing.T) {
	oldAccess, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	oldRefresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	newAccess, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	newRefresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "control_session_0123456789abcdef0123456789abcdef"
	refreshExpiresAt := time.Now().Add(24 * time.Hour).UTC()
	var oldRequests, newRequests, refreshCalls atomic.Int32
	allOldRequests := make(chan struct{})
	var closeOldRequests sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/capabilities":
			_ = json.NewEncoder(response).Encode(localCapabilities())
		case "GET /v1/routes":
			switch request.Header.Get("Authorization") {
			case "Bearer " + oldAccess.String():
				if oldRequests.Add(1) == 2 {
					closeOldRequests.Do(func() { close(allOldRequests) })
				}
				<-allOldRequests
				response.Header().Set("WWW-Authenticate", "Bearer")
				response.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(response).Encode(serverv1.Problem{Code: serverv1.Unauthenticated})
			case "Bearer " + newAccess.String():
				newRequests.Add(1)
				_, _ = response.Write([]byte("[]"))
			default:
				t.Errorf("routes authorization = %q", request.Header.Get("Authorization"))
				response.WriteHeader(http.StatusUnauthorized)
			}
		case "POST /v1/auth/refresh":
			refreshCalls.Add(1)
			var body serverv1.RefreshControlSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.RefreshToken != oldRefresh.String() {
				t.Errorf("refresh body = %#v, error = %v", body, err)
			}
			_ = json.NewEncoder(response).Encode(serverv1.ControlSessionResponse{
				SessionId: sessionID, AccessToken: newAccess.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
				RefreshToken: newRefresh.String(), RefreshExpiresAt: refreshExpiresAt,
				Grants: []serverv1.Grant{serverv1.Publish},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	stateRoot := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	store, err := state.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveControlSession(t.Context(), clientstate.ControlSession{
		Kind: clientstate.ControlSessionKindCore, ControlEndpoint: server.URL, SessionID: sessionID, Issuer: server.URL,
		AccessToken: oldAccess.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: oldRefresh.String(), RefreshExpiresAt: refreshExpiresAt, Grants: []string{"publish"},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := Authenticate(context.Background(), Config{
		CoreEndpoint: server.URL, State: state, HTTPClient: server.Client(), Diagnostics: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsFound := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := client.Core.ListRoutes(context.Background())
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, found, err := store.ControlSession(t.Context())
	if err != nil || !found || stored.AccessToken != newAccess.String() || stored.RefreshToken != newRefresh.String() {
		t.Fatalf("stored session = %#v, found = %v, error = %v", stored, found, err)
	}
	if oldRequests.Load() != 2 || newRequests.Load() != 2 || refreshCalls.Load() != 1 {
		t.Fatalf("old requests = %d, new requests = %d, refresh calls = %d", oldRequests.Load(), newRequests.Load(), refreshCalls.Load())
	}
}

func TestExplicitAccessTokenDoesNotOpenStateOrRefresh(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	session, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/capabilities":
			_ = json.NewEncoder(response).Encode(localCapabilities())
		case "/v1/routes":
			if request.Header.Get("Authorization") != "Bearer "+access.String() {
				t.Errorf("routes authorization = %q", request.Header.Get("Authorization"))
			}
			_, _ = response.Write([]byte("[]"))
		case "/v1/routes/route/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+session.String() {
				t.Errorf("heartbeat authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(serverv1.HeartbeatResponse{ExpiresAt: time.Now().Add(time.Minute)})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := Authenticate(context.Background(), Config{
		CoreEndpoint: server.URL, AccessToken: access.String(),
		HTTPClient: server.Client(), Diagnostics: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Core.ListRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Core.Heartbeat(context.Background(), "route", 1, session); err != nil {
		t.Fatal(err)
	}
}

func localCapabilities() serverv1.Capabilities {
	return serverv1.Capabilities{
		Authentication: serverv1.AuthenticationCapabilities{
			Required: serverv1.True, Methods: []serverv1.AuthenticationCapabilitiesMethods{serverv1.LoginToken},
		},
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
		HostnameSuffix:        "example", MaximumSubdomainDepth: 8,
	}
}
