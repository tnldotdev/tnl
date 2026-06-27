package controlclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestClientMapsProblemsAndRejectsTrailingJSON(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	session, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]interface{}{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/discovery":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/route-sessions/session/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+session.String() {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(response).Encode(controlv1.Problem{
				Type: "https://tnl.dev/problems/conflict", Title: "Conflict", Status: http.StatusConflict,
				Code: controlv1.Conflict, RequestId: "req_test", Details: &details,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discovery(t.Context()); err == nil {
		t.Fatal("Discovery accepted trailing JSON")
	}
	if _, err := client.Heartbeat(t.Context(), "session", 1, session); !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("Heartbeat error = %v, want status conflict", err)
	}
}

func TestClientBoundsRequests(t *testing.T) {
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	client.timeout = 20 * time.Millisecond
	if _, err := client.Discovery(context.Background()); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Discovery error = %v, want unavailable deadline", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
