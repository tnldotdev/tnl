package control

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

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestClientMapsProblemsAndRejectsTrailingJSON(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]interface{}{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/discovery":
			_, _ = response.Write([]byte(`{} {}`))
		case "/v1/services/svc_test/runs/srun_test/renew":
			if request.Header.Get("Authorization") != "Bearer "+session.String() {
				t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
			}
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(response).Encode(controlv1.Problem{
				Type: "https://tnl.dev/p/conflict", Title: "Conflict", Status: http.StatusConflict,
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
	if _, err := client.HeartbeatServiceRun(t.Context(), "svc_test", "srun_test", session, controlv1.ServiceRunHeartbeat{Healthy: true}); !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("HeartbeatServiceRun error = %v, want status conflict", err)
	}
}

func TestNameUnavailableRemainsDistinctFromStatusConflict(t *testing.T) {
	payload, err := json.Marshal(controlv1.Problem{
		Type: "https://tnl.dev/p/name-unavailable", Title: "service hostname is unavailable",
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

func TestClientPreservesInternalProblemInsteadOfRetryableOutage(t *testing.T) {
	for _, test := range []struct {
		code        controlv1.ProblemCode
		status      int
		unavailable bool
	}{
		{controlv1.Internal, 500, false},
		{controlv1.Forbidden, 502, false},
		{controlv1.Unavailable, 503, true},
		{controlv1.PlacementUnavailable, 503, true},
	} {
		t.Run(string(test.code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: test.code, Status: test.status,
					Title: "safe control problem", RequestId: "req_fixture"})
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Discovery(t.Context())
			var problem *ProblemError
			if errors.Is(err, ErrUnavailable) != test.unavailable || !errors.As(err, &problem) ||
				problem.Status != test.status || problem.Problem.RequestId != "req_fixture" {
				t.Fatal("control response lost its fault class or correlation facts", err)
			}
		})
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

func TestClientCancellationRetainsIndependentLostReply(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	client, err := New("https://server.example", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, io.ErrUnexpectedEOF
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Discovery(ctx)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("cancellation hid an independent response failure", err)
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
				if request.URL.Path != "/v1/services/svc_test" || request.Header.Get("Authorization") != "Bearer access" {
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
			if _, err := client.GetService(t.Context(), "svc_test"); err == nil {
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

func TestClientConfiguresServiceWithTrustRevision(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	want := controlv1.Service{
		Id: "svc_test", Name: "web", TeamId: "team_test", DomainId: new("domain_test"),
		Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, CreatedAt: created,
		TrustRevision: 5, EndpointRevision: 9, Ephemeral: true, ExpiresAt: &expires,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
		Placement: &controlv1.ServicePlacement{
			DomainId: new("domain_test"), Hostname: new("web.example.test"),
			WorktreeKey: new("worktree_test"), WorktreeLabel: new("checkout"),
		},
		HttpLimits: &controlv1.ProjectHTTPApplicationLimits{
			Total: new(20), Concurrency: new(3),
			Rate: &controlv1.ProjectApplicationRate{Count: 2, Per: "1m", Burst: new(7)},
		},
		RequirePostQuantum: true, ServiceRunId: new("srun_test"), RunNumber: new(int64(37)),
		Source: &controlv1.LocalServiceSource{
			ProjectKey: "project_test", Service: "web", SourceFingerprint: "source_test", WorktreeKey: "worktree_test",
		},
		TargetTls: &controlv1.ServiceTargetTLS{
			Hostname: "origin.internal", System: true,
			Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/v1/services/svc_test" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer access" || request.Header.Get("Accept") != "application/json, application/problem+json" || request.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect authentication or JSON negotiation headers")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		} else if string(body["protocol"]) != `"http"` || string(body["publisher_pool"]) != "false" || string(body["expected_trust_revision"]) != `"4"` {
			t.Errorf("update body = %#v", body)
		}
		var configuration struct {
			Target string `json:"target"`
			HTTP   struct {
				Access struct {
					Mode json.RawMessage `json:"mode"`
					IP   json.RawMessage `json:"ip"`
				} `json:"access"`
			} `json:"http"`
		}
		if err := json.Unmarshal(body["configuration"], &configuration); err != nil {
			t.Error(err)
		} else if configuration.Target != "app" || string(configuration.HTTP.Access.Mode) != `"restricted"` || string(configuration.HTTP.Access.IP) != "[]" {
			t.Errorf("configuration lost its explicit empty HTTP IP policy: %s", body["configuration"])
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(want); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	service, err := client.ConfigureService(t.Context(), "svc_test", controlv1.UpdateServiceRequest{
		Protocol: controlv1.ServiceProtocolHTTP, PublisherPool: false, ExpectedTrustRevision: 4,
		Configuration: &controlv1.ProjectServiceConfiguration{
			Target: "app", Http: &controlv1.ProjectServiceHTTP{
				Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted), Ip: new([]string{})},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(service, want) {
		t.Fatalf("updated service = %#v, want %#v", service, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
