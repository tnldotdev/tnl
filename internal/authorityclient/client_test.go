package authorityclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestAuthenticationRequestsUseAuthorityContract(t *testing.T) {
	const sessionJSON = `{"session_id":"control_session_0123456789abcdef0123456789abcdef","access_token":"issued-access","refresh_token":"issued-refresh","access_expires_at":"2030-01-01T00:00:00Z","refresh_expires_at":"2030-01-02T00:00:00Z"}`
	for _, test := range []struct {
		name, path, body string
		call             func(*Client) (authorityv1.ControlSessionResponse, error)
	}{
		{"login token", "/v1/auth/token", `{"login_token":"login-input"}`, func(c *Client) (authorityv1.ControlSessionResponse, error) {
			return c.Exchange(t.Context(), "login-input")
		}},
		{"OIDC", "/v1/auth/oidc", `{"id_token":"oidc-input"}`, func(c *Client) (authorityv1.ControlSessionResponse, error) {
			return c.ExchangeOIDC(t.Context(), "oidc-input")
		}},
		{"refresh", "/v1/auth/refresh", `{"refresh_token":"refresh-input"}`, func(c *Client) (authorityv1.ControlSessionResponse, error) {
			return c.Refresh(t.Context(), "refresh-input")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			body := &responseBody{Reader: strings.NewReader(sessionJSON)}
			var requestContext context.Context
			client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				requestContext = request.Context()
				defer request.Body.Close()
				payload, err := io.ReadAll(request.Body)
				if err != nil {
					return nil, err
				}
				if request.Method != http.MethodPost || request.URL.String() != "https://authority.example"+test.path || request.Header.Get("Authorization") != "" || request.Header.Get("Accept") != "application/json, application/problem+json" || request.Header.Get("Content-Type") != "application/json" || string(payload) != test.body {
					t.Errorf("unexpected auth request: %s %s", request.Method, request.URL)
				}
				deadline, bounded := request.Context().Deadline()
				if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > defaultRequestTimeout {
					t.Error("request lacks bounded deadline")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}, "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := test.call(client)
			want := authorityv1.ControlSessionResponse{SessionId: "control_session_0123456789abcdef0123456789abcdef", AccessToken: "issued-access", RefreshToken: "issued-refresh", AccessExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), RefreshExpiresAt: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)}
			if err != nil || !reflect.DeepEqual(got, want) || calls != 1 || !body.closed {
				t.Fatalf("session response mismatch: calls=%d closed=%v error=%v", calls, body.closed, err)
			}
			if !errors.Is(requestContext.Err(), context.Canceled) {
				t.Fatal("completed request context was not released")
			}
		})
	}
}

func TestExplicitAccessTokenOverridesConfiguredToken(t *testing.T) {
	for _, test := range []struct {
		name, method, path, wantToken string
		call                          func(*Client) error
	}{
		{"identity default", http.MethodGet, "/v1/identity", "configured-access", func(c *Client) error { _, err := c.IdentityContext(t.Context()); return err }},
		{"identity explicit", http.MethodGet, "/v1/identity", "explicit-access", func(c *Client) error {
			_, err := c.IdentityContextWithAccessToken(t.Context(), "explicit-access")
			return err
		}},
		{"logout explicit", http.MethodPost, "/v1/auth/logout", "explicit-access", func(c *Client) error { return c.LogoutWithAccessToken(t.Context(), "explicit-access") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != test.method || request.URL.String() != "https://authority.example"+test.path || request.Header.Get("Authorization") != "Bearer "+test.wantToken || request.Header.Get("Accept") != "application/json, application/problem+json" || request.Body != nil {
					t.Errorf("unexpected authorized request: %s %s", request.Method, request.URL)
				}
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}, "configured-access")
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(client); err != nil || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestRequestCancellationPreservesCauseAndReturnsNoSession(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		defer request.Body.Close()
		cancel()
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Refresh(ctx, "refresh")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, authorityv1.ControlSessionResponse{}) || calls != 1 {
		t.Fatalf("canceled refresh: calls=%d error=%v", calls, err)
	}
}
