// Package controlclient calls the tnl control API.
//
// responses cannot exceed 64 KiB. a successful response other than HTTP 204
// must contain one non-null JSON value that matches the generated schema. most
// requests time out after 20 seconds; certificate requests time out after 150
// seconds. requests do not follow redirects. network and read failures wrap
// ErrUnavailable, but caller cancellation, invalid responses, and oversized
// responses do not. known server problem codes take precedence over status.
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
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maxResponseBytes       = 1 << 20
	defaultRequestTimeout  = 20 * time.Second
	certificateCallTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated   = failure.Wrap("authenticate control request", failure.Authentication, errors.New("controlclient: unauthenticated"))
	ErrNotFound          = failure.Wrap("read control resource", failure.ServerResourceNotFound, errors.New("controlclient: not found"))
	ErrNameUnavailable   = failure.Wrap("select public URL hostname", failure.ServerConflict, errors.New("controlclient: public URL hostname unavailable"))
	ErrStatusConflict    = failure.Wrap("update control state", failure.ServerConflict, errors.New("controlclient: status conflict"))
	ErrCertificateStatus = failure.Wrap("issue public URL certificate", failure.CertificateUnavailable, errors.New("controlclient: certificate status conflict"))
	ErrDNSProofPending   = failure.Wrap("configure domain DNS", failure.DNSPending, errors.New("controlclient: DNS setup pending"))
	ErrRateLimited       = failure.Wrap("request control API", failure.ServerRateLimited, errors.New("controlclient: rate limited"))
	ErrUnavailable       = failure.Wrap("request control API", failure.ServerUnavailable, errors.New("controlclient: temporarily unavailable"))
	ErrUnsupported       = failure.Wrap("request control API", failure.ServerResponseInvalid, errors.New("controlclient: unsupported"))
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
		return nil, failure.Wrap("select control server", failure.InvalidControlURL, err)
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
		return nil, failure.Wrap("configure control client", failure.ServerRequestInvalid, err)
	}
	return &Client{api: apiClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	return request[controlv1.ControlDiscovery](ctx, c, "", c.api.GetControlDiscovery)
}

func (c *Client) ClientIP(ctx context.Context) (controlv1.ClientIPResponse, error) {
	return request[controlv1.ClientIPResponse](ctx, c, "", c.api.GetClientIP)
}

func (c *Client) CreatePublicURL(ctx context.Context, body controlv1.CreatePublicURLRequest, idempotencyKey string) (controlv1.PublicURL, error) {
	params := &controlv1.CreatePublicURLParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[controlv1.PublicURL](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublicURL(ctx, params, body, editors...)
	})
}

func (c *Client) ListPublicURLs(ctx context.Context, teamID string) ([]controlv1.PublicURL, error) {
	var routes []controlv1.PublicURL
	cursor := ""
	for {
		params := &controlv1.ListPublicURLsParams{TeamId: teamID}
		if cursor != "" {
			params.Cursor = &cursor
		}
		page, err := requestWithAccess[controlv1.PublicURLPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListPublicURLs(ctx, params, editors...)
		})
		if err != nil {
			return nil, err
		}
		routes = append(routes, page.PublicUrls...)
		if page.NextCursor == nil {
			return routes, nil
		}
		if len(page.PublicUrls) == 0 || *page.NextCursor == cursor {
			return nil, failure.Wrap("list public URLs", failure.ServerResponseInvalid, errors.New("controlclient: invalid public URL cursor"))
		}
		cursor = *page.NextCursor
	}
}

// GetPublicURLByHostname uses one filtered request instead of paging through a
// team's public URLs. reject unfiltered responses from servers ignoring the filter.
func (c *Client) GetPublicURLByHostname(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if teamID == "" || err != nil || canonical != hostname {
		return controlv1.PublicURL{}, failure.Wrap("find public URL", failure.ServerRequestInvalid, errors.New("controlclient: team and canonical hostname are required"))
	}
	params := &controlv1.ListPublicURLsParams{TeamId: teamID, CanonicalHostname: &hostname}
	page, err := requestWithAccess[controlv1.PublicURLPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPublicURLs(ctx, params, editors...)
	})
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	if page.NextCursor != nil || len(page.PublicUrls) > 1 {
		return controlv1.PublicURL{}, failure.Wrap("find public URL", failure.ServerResponseInvalid, errors.New("controlclient: server returned an unfiltered hostname lookup"))
	}
	if len(page.PublicUrls) == 0 {
		return controlv1.PublicURL{}, ErrNotFound
	}
	route := page.PublicUrls[0]
	if route.Id == "" || route.TeamId != teamID || route.CanonicalHostname != hostname ||
		(route.LifecycleState != controlv1.Enabled && route.LifecycleState != controlv1.Suspended) {
		return controlv1.PublicURL{}, failure.Wrap("find public URL", failure.ServerResponseInvalid, errors.New("controlclient: server returned an invalid hostname lookup"))
	}
	return route, nil
}

func (c *Client) GetPublicURL(ctx context.Context, publicURLID string) (controlv1.PublicURL, error) {
	return requestWithAccess[controlv1.PublicURL](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPublicURL(ctx, publicURLID, editors...)
	})
}

func (c *Client) UpdatePublicURL(ctx context.Context, publicURLID string, body controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	return requestWithAccess[controlv1.PublicURL](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.UpdatePublicURL(ctx, publicURLID, body, editors...)
	})
}

func (c *Client) DeletePublicURL(ctx context.Context, publicURLID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeletePublicURL(ctx, publicURLID, editors...)
	})
	return err
}

func (c *Client) CreatePublishRun(ctx context.Context, publicURLID, idempotencyKey string) (controlv1.PublishRunSetup, error) {
	params := &controlv1.CreatePublishRunParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[controlv1.PublishRunSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublishRun(ctx, publicURLID, params, editors...)
	})
}

func (c *Client) MarkPublishRunReady(ctx context.Context, publishRunID string, publishRunNumber uint64, token credentials.PublishRunToken) error {
	body := controlv1.PublishRunVersionRequest{PublishRunNumber: int64(publishRunNumber)}
	_, err := request[controlv1.PublishRun](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkPublishRunReady(ctx, publishRunID, body, editors...)
	})
	return err
}

func (c *Client) HeartbeatPublishRun(ctx context.Context, publishRunID string, publishRunNumber uint64, token credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	body := controlv1.PublishRunVersionRequest{PublishRunNumber: int64(publishRunNumber)}
	return request[controlv1.PublishRunHeartbeat](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatPublishRun(ctx, publishRunID, body, editors...)
	})
}

func (c *Client) ClosePublishRun(ctx context.Context, publishRunID string, token credentials.PublishRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ClosePublishRun(ctx, publishRunID, editors...)
	})
	return err
}

func (c *Client) CreateCertificateIssuance(ctx context.Context, publishRunID string, publishRunNumber uint64, token credentials.PublishRunToken, csrDER []byte, idempotencyKey string) (controlv1.CertificateIssuance, error) {
	params := &controlv1.CreateCertificateIssuanceParams{IdempotencyKey: idempotencyKey}
	body := controlv1.CreateCertificateIssuanceRequest{PublishRunNumber: int64(publishRunNumber), Csr: csrDER}
	return requestWithTimeout[controlv1.CertificateIssuance](ctx, c, certificateCallTimeout, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateCertificateIssuance(ctx, publishRunID, params, body, editors...)
	})
}

func (c *Client) GetCertificateIssuance(ctx context.Context, issuanceID string, token credentials.PublishRunToken) (controlv1.CertificateIssuance, error) {
	return request[controlv1.CertificateIssuance](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetCertificateIssuance(ctx, issuanceID, editors...)
	})
}

func (c *Client) MarkCertificateChallengeReady(ctx context.Context, issuanceID string, token credentials.PublishRunToken) (controlv1.CertificateIssuance, error) {
	return requestWithTimeout[controlv1.CertificateIssuance](ctx, c, certificateCallTimeout, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkCertificateChallengeReady(ctx, issuanceID, editors...)
	})
}

func (c *Client) MarkCertificateChallengeRemoved(ctx context.Context, issuanceID string, token credentials.PublishRunToken) error {
	_, err := request[controlv1.CertificateIssuance](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkCertificateChallengeRemoved(ctx, issuanceID, editors...)
	})
	return err
}

func (c *Client) MarkPublishRunCertificateInstalled(ctx context.Context, publishRunID string, publishRunNumber uint64, issuanceID string, notAfter time.Time, token credentials.PublishRunToken) error {
	body := controlv1.CertificateInstalledRequest{PublishRunNumber: int64(publishRunNumber), IssuanceId: issuanceID, NotAfter: notAfter}
	_, err := request[controlv1.PublishRun](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkPublishRunCertificateInstalled(ctx, publishRunID, body, editors...)
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
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: response exceeds limit"))
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
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: successful response has an empty body"))
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: successful response has a null body"))
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var result T
	err = httpjson.Decode(decoder, &result)
	if errors.Is(err, httpjson.ErrTrailingContent) {
		return zero, failure.Wrap("decode control response", failure.ServerResponseInvalid, errors.New("controlclient: response contains trailing JSON"))
	}
	if err != nil {
		return zero, failure.Wrap("decode control response", failure.ServerResponseInvalid, err)
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
		return failure.Wrap("request control API", failure.ServerResponseInvalid, fmt.Errorf("controlclient: HTTP %d", status))
	}
	switch problem.Code {
	case controlv1.Unauthenticated:
		return ErrUnauthenticated
	case controlv1.NotFound:
		return ErrNotFound
	case controlv1.NameUnavailable:
		return ErrNameUnavailable
	case controlv1.Conflict, controlv1.PublishRunOpen, controlv1.PolicyRevisionStale:
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
		cause := &ProblemError{Status: status, Problem: problem}
		if status == http.StatusForbidden {
			return failure.Wrap("request control API", failure.ServerDenied, cause)
		}
		return failure.Wrap("request control API", failure.ServerRequestInvalid, cause)
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
