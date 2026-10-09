package clientruntime

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unreadBody struct {
	t      *testing.T
	closed bool
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
				if request.Method != "GET" || request.URL.String() != "https://app.example/" || request.Header.Get(ProbeHeader) != "1" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
					t.Fatalf("probe = %#v", request)
				}
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("probe lacks a bounded deadline")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.example"}}, Body: body, Request: request}, nil
			}))
			want := status >= 200 && status <= 499 && status != 408 && status != 429
			if observation.Ready != want || calls != 1 || !body.closed || observation.RegistrationID != "registration" || observation.PublishRunNumber != 7 {
				t.Fatalf("readiness = %#v, calls = %d", observation, calls)
			}
		})
	}
}

func TestDiagnosticsAlwaysFailAndExactStatusCanBeRequired(t *testing.T) {
	for _, test := range []struct {
		status     int
		diagnostic string
		want       bool
	}{{204, "", true}, {200, "", false}, {204, "TNL_IP_POLICY_DENIED", false}, {403, "TNL_IP_POLICY_DENIED", false}} {
		observation := Probe(context.Background(), Service{PublicURL: "https://app.example", Readiness: Readiness{Path: "/health", Status: 204}}, roundTrip(func(request *http.Request) (*http.Response, error) {
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
