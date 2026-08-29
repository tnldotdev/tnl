package coreclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

func TestClientMapsProblemsAndRejectsTrailingJSON(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	lease, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/routes/route/heartbeat":
			if request.Header.Get("Authorization") != "Bearer "+lease.String() {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(response).Encode(corev1.Problem{
				Type: "https://tnl.dev/problems/state-conflict", Title: "State conflict",
				Status: http.StatusConflict, Code: corev1.StateConflict, RequestId: "req_test", Details: map[string]interface{}{},
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
	if _, err := client.Capabilities(context.Background()); err == nil {
		t.Fatal("Capabilities accepted trailing JSON")
	}
	if _, err := client.Heartbeat(context.Background(), "route", 1, lease); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Heartbeat error = %v, want state conflict", err)
	}
}

func TestClientBoundsRequests(t *testing.T) {
	client, err := New("https://core.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	client.timeout = 20 * time.Millisecond
	if _, err := client.Capabilities(context.Background()); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capabilities error = %v, want unavailable deadline", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
