package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unreadBody struct {
	t      *testing.T
	closed bool
}

func assertProbeOutcome(t *testing.T, m *observability.Metrics, want string) {
	t.Helper()
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "tnl_publisher_operation_duration_seconds" {
			continue
		}
		for _, point := range family.Metric {
			for _, label := range point.Label {
				if label.GetName() == "tnl_outcome" && label.GetValue() == want && point.GetHistogram().GetSampleCount() == 1 {
					return
				}
			}
		}
	}
	t.Fatal("readiness completion lost its outcome", want, families)
}

func TestReadiness503IsFailureBeforeProbeCleanup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	m := observability.New("publisher")
	defer m.Shutdown(t.Context())
	observation := ProbeWithProof(observability.WithMetrics(t.Context(), m), Service{PublicURL: server.URL}, server.Client().Transport, "proof")
	if observation.Ready || observation.Status != 503 {
		t.Fatal(observation)
	}
	assertProbeOutcome(t, m, "error")
}

func TestReadinessTimeoutAndParentCancellationRemainDistinct(t *testing.T) {
	for _, parentCanceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "probe timeout", true: "parent canceled"}[parentCanceled], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := observability.New("publisher")
				defer m.Shutdown(context.Background())
				ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
				defer cancel()
				observation := ProbeWithProof(ctx, Service{PublicURL: "https://fixture.invalid"}, roundTrip(func(r *http.Request) (*http.Response, error) {
					if parentCanceled {
						cancel()
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				}), "")
				if observation.Ready {
					t.Fatal(observation)
				}
				want := "timeout"
				if parentCanceled {
					want = "canceled"
				}
				assertProbeOutcome(t, m, want)
			})
		})
	}
}

func (b *unreadBody) Read([]byte) (int, error) {
	b.t.Error("readiness consumed a response body")
	return 0, io.EOF
}
func (b *unreadBody) Close() error { b.closed = true; return nil }

func TestPublicReadinessUsesHeadersOnlyAndDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{200, 204, 301, 302, 401, 404, 408, 429, 499, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &unreadBody{t: t}
			calls := 0
			observation := Probe(t.Context(), Service{RegistrationID: "registration", PublishRunNumber: 7, PublicURL: "https://app.example"}, roundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != "GET" || request.URL.String() != "https://app.example/" || request.Header.Get(ProbeHeader) != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
					t.Fatalf("probe = %#v", request)
				}
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("probe lacks a bounded deadline")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.example"}}, Body: body, Request: request}, nil
			}))
			want := status >= 200 && status < 300
			if observation.Ready != want || calls != 1 || !body.closed || observation.RegistrationID != "registration" || observation.PublishRunNumber != 7 {
				t.Fatalf("readiness = %#v, calls = %d", observation, calls)
			}
		})
	}
}

func TestDiagnosticsAlwaysFailAndReadinessUsesConfiguredPath(t *testing.T) {
	for _, test := range []struct {
		status     int
		diagnostic string
		want       bool
	}{{204, "", true}, {200, "", true}, {204, "TNL_IP_POLICY_DENIED", false}, {403, "TNL_IP_POLICY_DENIED", false}} {
		observation := Probe(context.Background(), Service{PublicURL: "https://app.example", Readiness: Readiness{Path: "/health"}}, roundTrip(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/health" {
				t.Fatal("wrong readiness path")
			}
			return &http.Response{StatusCode: test.status, Header: http.Header{DiagnosticHeader: []string{test.diagnostic}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}))
		if observation.Ready != test.want {
			t.Fatalf("readiness = %#v", observation)
		}
	}
	if RetryDelay(0) != 500*time.Millisecond || RetryDelay(1) != time.Second || RetryDelay(20) != 2*time.Second {
		t.Fatal("wrong retry schedule")
	}
}
