package controlclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	session, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]interface{}{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/discovery":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/publish-runs/session/heartbeat":
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
	if _, err := client.HeartbeatPublishRun(t.Context(), "session", 1, session); !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("HeartbeatPublishRun error = %v, want status conflict", err)
	}
}

func TestNameUnavailableRemainsDistinctFromStatusConflict(t *testing.T) {
	payload, err := json.Marshal(controlv1.Problem{
		Type: "https://tnl.dev/problems/name_unavailable", Title: "route hostname is unavailable",
		Status: http.StatusConflict, Code: controlv1.NameUnavailable, RequestId: "request_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = responseError(http.StatusConflict, nil, payload)
	if !errors.Is(err, ErrNameUnavailable) || errors.Is(err, ErrStatusConflict) {
		t.Fatalf("response error = %v", err)
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

func TestClientPreservesParentCancellationCause(t *testing.T) {
	cause := errors.New("caller stopped")
	ctx, cancel := context.WithCancelCause(t.Context())
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		cancel(cause)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discovery(ctx); !errors.Is(err, cause) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Discovery error = %v, want caller cause only", err)
	}
}

func TestClientPreservesParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discovery(ctx); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Discovery error = %v, want caller deadline only", err)
	}
}

func TestClientDoesNotFollowAuthenticatedRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			destinationCalls := 0
			destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				destinationCalls++
				_, _ = io.Copy(io.Discard, request.Body)
			}))
			defer destination.Close()

			source := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v1/public-urls/public_url_1" || request.Header.Get("Authorization") != "Bearer access" {
					t.Errorf("unexpected authenticated request: %s %s", request.Method, request.URL)
				}
				response.Header().Set("Location", destination.URL+"/record")
				response.WriteHeader(status)
			}))
			defer source.Close()

			supplied := source.Client()
			client, err := New(source.URL, supplied, "access")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetPublicURL(t.Context(), "public_url_1"); err == nil {
				t.Fatal("redirect response was accepted")
			}
			if destinationCalls != 0 {
				t.Fatalf("credential-bearing request reached redirect destination %d times", destinationCalls)
			}
			if supplied.CheckRedirect != nil {
				t.Fatal("supplied client was mutated")
			}
		})
	}
}

func TestClientUpdatesPublicURL(t *testing.T) {
	target := "http://127.0.0.1:4000"
	prefixes := []string{}
	want := controlv1.PublicURL{
		Id: "public_url_1", TeamId: "team_1", DomainId: "domain_1", CanonicalHostname: "demo.example",
		Target: target, AllowedIpPrefixes: &prefixes, PublicUrlScope: "member", PolicyRevision: 2,
		LifecycleState: "enabled", NextPublishRunNumber: 3,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPatch || request.URL.Path != "/v1/public-urls/public_url_1" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer access" || request.Header.Get("Accept") != "application/json, application/problem+json" || request.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect authentication or JSON negotiation headers")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		} else if string(body["target"]) != `"http://127.0.0.1:4000"` || string(body["allowed_ip_prefixes"]) != "[]" {
			t.Errorf("update body = %#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(want)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	route, err := client.UpdatePublicURL(t.Context(), "public_url_1", controlv1.UpdatePublicURLRequest{
		Target: target, AllowedIpPrefixes: prefixes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(route, want) {
		t.Fatalf("updated route = %#v", route)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
