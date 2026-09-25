// Package controlclient calls the tnl control API.
//
// Responses cannot exceed 64 KiB. A successful response other than HTTP 204
// must contain one non-null JSON value that matches the generated schema. Most
// requests time out after 20 seconds; certificate requests time out after 150
// seconds. Requests do not follow redirects. Network and read failures wrap
// ErrUnavailable, but caller cancellation, invalid responses, and oversized
// responses do not. Known server problem codes take precedence over status.
package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maxResponseBytes       = 64 << 10
	defaultRequestTimeout  = 20 * time.Second
	certificateCallTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated   = errors.New("controlclient: unauthenticated")
	ErrNotFound          = errors.New("controlclient: not found")
	ErrNameUnavailable   = errors.New("controlclient: route hostname unavailable")
	ErrStatusConflict    = errors.New("controlclient: status conflict")
	ErrCertificateStatus = errors.New("controlclient: certificate status conflict")
	ErrDNSProofPending   = errors.New("controlclient: DNS setup pending")
	ErrRateLimited       = errors.New("controlclient: rate limited")
	ErrUnavailable       = errors.New("controlclient: temporarily unavailable")
	ErrUnsupported       = errors.New("controlclient: unsupported")
)

type Client struct {
	api                    *controlv1.Client
	access                 credentials.AccessToken
	externalAuthentication bool
	timeout                time.Duration
}

// NewExternallyAuthenticated creates a client whose HTTP transport adds authorization.
func NewExternallyAuthenticated(server string, httpClient *http.Client) (*Client, error) {
	client, err := New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	client.externalAuthentication = true
	return client, nil
}

func New(server string, httpClient *http.Client, access credentials.AccessToken) (*Client, error) {
	server, err := clientstate.CanonicalServer(server)
	if err != nil {
		return nil, errors.New("controlclient: tnl server must be an HTTPS origin")
	}
	httpClient = httpclient.NoRedirects(httpClient)
	apiClient, err := controlv1.NewClient(
		server,
		controlv1.WithHTTPClient(httpClient),
		controlv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Accept", "application/json, application/problem+json")
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("controlclient: configure generated client: %w", err)
	}
	return &Client{api: apiClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	return request[controlv1.ControlDiscovery](ctx, c, "", c.api.GetControlDiscovery)
}

func (c *Client) ClientIP(ctx context.Context) (controlv1.ClientIPResponse, error) {
	return request[controlv1.ClientIPResponse](ctx, c, "", c.api.GetClientIP)
}

func (c *Client) CreateRoute(ctx context.Context, body controlv1.CreateRouteRequest, idempotencyKey string) (controlv1.Route, error) {
	params := &controlv1.CreateRouteParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[controlv1.Route](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRoute(ctx, params, body, editors...)
	})
}

func (c *Client) ListRoutes(ctx context.Context, teamID string) ([]controlv1.Route, error) {
	var routes []controlv1.Route
	cursor := ""
	for {
		params := &controlv1.ListRoutesParams{TeamId: teamID}
		if cursor != "" {
			params.Cursor = &cursor
		}
		page, err := requestWithAccess[controlv1.RoutePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListRoutes(ctx, params, editors...)
		})
		if err != nil {
			return nil, err
		}
		routes = append(routes, page.Routes...)
		if page.NextCursor == nil {
			return routes, nil
		}
		if len(page.Routes) == 0 || *page.NextCursor == cursor {
			return nil, errors.New("controlclient: invalid route cursor")
		}
		cursor = *page.NextCursor
	}
}

// GetRouteByHostname uses one filtered request instead of paging through a
// team's routes. Reject unfiltered responses from servers ignoring the filter.
func (c *Client) GetRouteByHostname(ctx context.Context, teamID, hostname string) (controlv1.Route, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if teamID == "" || err != nil || canonical != hostname {
		return controlv1.Route{}, errors.New("controlclient: team and canonical hostname are required")
	}
	params := &controlv1.ListRoutesParams{TeamId: teamID, CanonicalHostname: &hostname}
	page, err := requestWithAccess[controlv1.RoutePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListRoutes(ctx, params, editors...)
	})
	if err != nil {
		return controlv1.Route{}, err
	}
	if page.NextCursor != nil || len(page.Routes) > 1 {
		return controlv1.Route{}, errors.New("controlclient: server returned an unfiltered hostname lookup")
	}
	if len(page.Routes) == 0 {
		return controlv1.Route{}, ErrNotFound
	}
	route := page.Routes[0]
	if route.Id == "" || route.TeamId != teamID || route.CanonicalHostname != hostname ||
		(route.LifecycleState != controlv1.Enabled && route.LifecycleState != controlv1.Suspended) {
		return controlv1.Route{}, errors.New("controlclient: server returned an invalid hostname lookup")
	}
	return route, nil
}

func (c *Client) GetRoute(ctx context.Context, routeID string) (controlv1.Route, error) {
	return requestWithAccess[controlv1.Route](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetRoute(ctx, routeID, editors...)
	})
}

func (c *Client) UpdateRoute(ctx context.Context, routeID string, body controlv1.UpdateRouteRequest) (controlv1.Route, error) {
	return requestWithAccess[controlv1.Route](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.UpdateRoute(ctx, routeID, body, editors...)
	})
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteRoute(ctx, routeID, editors...)
	})
	return err
}

func (c *Client) CreateRouteSession(ctx context.Context, routeID, idempotencyKey string) (controlv1.RouteSessionSetup, error) {
	params := &controlv1.CreateRouteSessionParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[controlv1.RouteSessionSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRouteSession(ctx, routeID, params, editors...)
	})
}

func (c *Client) MarkRouteSessionReady(ctx context.Context, routeSessionID string, routeVersion uint64, token credentials.RouteSessionToken) error {
	body := controlv1.RouteSessionVersionRequest{RouteVersion: int64(routeVersion)}
	_, err := request[controlv1.RouteSession](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkRouteSessionReady(ctx, routeSessionID, body, editors...)
	})
	return err
}

func (c *Client) HeartbeatRouteSession(ctx context.Context, routeSessionID string, routeVersion uint64, token credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
	body := controlv1.RouteSessionVersionRequest{RouteVersion: int64(routeVersion)}
	return request[controlv1.RouteSessionHeartbeat](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatRouteSession(ctx, routeSessionID, body, editors...)
	})
}

func (c *Client) CloseRouteSession(ctx context.Context, routeSessionID string, token credentials.RouteSessionToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CloseRouteSession(ctx, routeSessionID, editors...)
	})
	return err
}

func (c *Client) CreateCertificateIssuance(ctx context.Context, routeSessionID string, routeVersion uint64, token credentials.RouteSessionToken, csrDER []byte, idempotencyKey string) (controlv1.CertificateIssuance, error) {
	params := &controlv1.CreateCertificateIssuanceParams{IdempotencyKey: idempotencyKey}
	body := controlv1.CreateCertificateIssuanceRequest{RouteVersion: int64(routeVersion), Csr: csrDER}
	return requestWithTimeout[controlv1.CertificateIssuance](ctx, c, certificateCallTimeout, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateCertificateIssuance(ctx, routeSessionID, params, body, editors...)
	})
}

func (c *Client) GetCertificateIssuance(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return request[controlv1.CertificateIssuance](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetCertificateIssuance(ctx, issuanceID, editors...)
	})
}

func (c *Client) MarkCertificateChallengeReady(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return requestWithTimeout[controlv1.CertificateIssuance](ctx, c, certificateCallTimeout, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkCertificateChallengeReady(ctx, issuanceID, editors...)
	})
}

func (c *Client) MarkCertificateChallengeRemoved(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) error {
	_, err := request[controlv1.CertificateIssuance](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkCertificateChallengeRemoved(ctx, issuanceID, editors...)
	})
	return err
}

func (c *Client) MarkRouteSessionCertificateInstalled(ctx context.Context, routeSessionID string, routeVersion uint64, issuanceID string, notAfter time.Time, token credentials.RouteSessionToken) error {
	body := controlv1.CertificateInstalledRequest{RouteVersion: int64(routeVersion), IssuanceId: issuanceID, NotAfter: notAfter}
	_, err := request[controlv1.RouteSession](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkRouteSessionCertificateInstalled(ctx, routeSessionID, body, editors...)
	})
	return err
}

type controlRequest func(context.Context, ...controlv1.RequestEditorFn) (*http.Response, error)

func requestWithAccess[T any](ctx context.Context, client *Client, call controlRequest) (T, error) {
	access, err := client.currentAccessToken()
	if err != nil {
		var zero T
		return zero, err
	}
	return requestWithTimeout[T](ctx, client, client.timeout, access.String(), call)
}

func (c *Client) currentAccessToken() (credentials.AccessToken, error) {
	if c.externalAuthentication {
		return "", nil
	}
	if c.access == "" {
		return "", ErrUnauthenticated
	}
	return c.access, nil
}

func request[T any](ctx context.Context, client *Client, token string, call controlRequest) (T, error) {
	return requestWithTimeout[T](ctx, client, client.timeout, token, call)
}

func requestWithTimeout[T any](ctx context.Context, client *Client, timeout time.Duration, token string, call controlRequest) (T, error) {
	var zero T
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := call(requestCtx, func(_ context.Context, request *http.Request) error {
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		return nil
	})
	if err != nil {
		return zero, unavailableError(ctx, err)
	}
	defer response.Body.Close()
	payload, err := httpjson.ReadAll(response.Body, maxResponseBytes)
	if errors.Is(err, httpjson.ErrTooLarge) {
		return zero, errors.New("controlclient: response exceeds limit")
	}
	if err != nil {
		return zero, unavailableError(ctx, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, responseError(response.StatusCode, response.Header, payload)
	}
	if response.StatusCode == http.StatusNoContent && len(payload) == 0 {
		return zero, nil
	}
	if len(payload) == 0 {
		return zero, errors.New("controlclient: successful response has an empty body")
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return zero, errors.New("controlclient: successful response has a null body")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var result T
	err = httpjson.Decode(decoder, &result)
	if errors.Is(err, httpjson.ErrTrailingContent) {
		return zero, errors.New("controlclient: response contains trailing JSON")
	}
	if err != nil {
		return zero, fmt.Errorf("controlclient: decode response: %w", err)
	}
	return result, nil
}

func unavailableError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func responseError(status int, header http.Header, payload []byte) error {
	var problem controlv1.Problem
	if json.Unmarshal(payload, &problem) != nil {
		return fmt.Errorf("controlclient: HTTP %d", status)
	}
	switch problem.Code {
	case controlv1.Unauthenticated:
		return ErrUnauthenticated
	case controlv1.NotFound:
		return ErrNotFound
	case controlv1.NameUnavailable:
		return ErrNameUnavailable
	case controlv1.Conflict, controlv1.RouteSessionOpen, controlv1.PolicyRevisionStale:
		return ErrStatusConflict
	case controlv1.DnsSetupPending:
		return ErrDNSProofPending
	case controlv1.IssuanceRetry:
		return ErrCertificateStatus
	case controlv1.RateLimited:
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		return &RateLimitError{RetryAfter: time.Duration(min(seconds, 86400)) * time.Second}
	case controlv1.Unavailable, controlv1.PlacementUnavailable, controlv1.Internal:
		return ErrUnavailable
	default:
		if status >= 500 && status < 600 && problem.Code.Valid() {
			return ErrUnavailable
		}
		return &ProblemError{Status: status, Problem: problem}
	}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "controlclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem controlv1.Problem
}

func (e *ProblemError) Error() string {
	return "controlclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}
