// Package serverclient is the bounded client for the tnl server API.
package serverclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/serverv1"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
)

const (
	maxResponseBytes      = 64 << 10
	defaultRequestTimeout = 20 * time.Second
	// Challenge requests include server-side probing and ACME finalization.
	challengeRequestTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated  = errors.New("serverclient: unauthenticated")
	ErrNotFound         = errors.New("serverclient: not found")
	ErrStateConflict    = errors.New("serverclient: state conflict")
	ErrCertificateState = errors.New("serverclient: certificate precondition failed")
	ErrRateLimited      = errors.New("serverclient: rate limited")
	ErrUnavailable      = errors.New("serverclient: temporarily unavailable")
)

type Client struct {
	base    *url.URL
	http    *http.Client
	access  credentials.AccessToken
	timeout time.Duration
}

func New(server string, httpClient *http.Client, access credentials.AccessToken) (*Client, error) {
	server, err := clientstate.CanonicalServer(server)
	if err != nil {
		return nil, errors.New("serverclient: server must be an HTTPS origin")
	}
	base, err := url.Parse(server)
	if err != nil {
		return nil, errors.New("serverclient: server must be an HTTPS origin")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	base.Path = ""
	return &Client{base: base, http: httpClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Capabilities(ctx context.Context) (serverv1.Capabilities, error) {
	return request[serverv1.Capabilities](ctx, c, http.MethodGet, "/v1/capabilities", "", nil)
}

func (c *Client) RelayMap(ctx context.Context) ([]byte, error) {
	data, err := request[json.RawMessage](ctx, c, http.MethodGet, "/v1/transport/relay-map", "", nil)
	return []byte(data), err
}

func (c *Client) Exchange(ctx context.Context, token credentials.LoginToken) (serverv1.TokenExchangeResponse, error) {
	return request[serverv1.TokenExchangeResponse](ctx, c, http.MethodPost, "/v1/auth/token", "", serverv1.TokenExchangeRequest{
		LoginToken: token.String(),
	})
}

func (c *Client) ExchangeOIDC(ctx context.Context, token string) (serverv1.TokenExchangeResponse, error) {
	return request[serverv1.TokenExchangeResponse](ctx, c, http.MethodPost, "/v1/auth/oidc", "", serverv1.OIDCTokenExchangeRequest{
		IdToken: token,
	})
}

func (c *Client) RevokeAccessCredential(ctx context.Context, credentialID string) error {
	_, err := request[struct{}](
		ctx, c, http.MethodDelete, "/v1/auth/credentials/"+url.PathEscape(credentialID), c.access.String(), nil,
	)
	return err
}

func (c *Client) CreateRoute(ctx context.Context, requestBody serverv1.CreateRouteRequest) (serverv1.LeaseSetup, error) {
	return request[serverv1.LeaseSetup](ctx, c, http.MethodPost, "/v1/routes", c.access.String(), requestBody)
}

func (c *Client) ListRoutes(ctx context.Context) ([]serverv1.Route, error) {
	return request[[]serverv1.Route](ctx, c, http.MethodGet, "/v1/routes", c.access.String(), nil)
}

func (c *Client) ClaimHostname(ctx context.Context, label, requestKey string) (serverv1.HostnameClaim, error) {
	requestBody := serverv1.CreateHostnameClaimRequest{}
	if label != "" {
		requestBody.Label = &label
	}
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return requestWithTimeout[serverv1.HostnameClaim](
		ctx, c, c.timeout, http.MethodPost, "/v1/hostname-claims", c.access.String(), requestBody, headers,
	)
}

func (c *Client) ListHostnameClaims(ctx context.Context) ([]serverv1.HostnameClaim, error) {
	var claims []serverv1.HostnameClaim
	cursor := ""
	for {
		page, next, err := c.ListHostnameClaimsPage(ctx, cursor)
		if err != nil {
			return nil, err
		}
		claims = append(claims, page...)
		if next == "" {
			return claims, nil
		}
		cursor = next
	}
}

func (c *Client) ListHostnameClaimsPage(
	ctx context.Context,
	cursor string,
) ([]serverv1.HostnameClaim, string, error) {
	query := make(url.Values)
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	page, err := requestWithTimeoutAndQuery[serverv1.HostnameClaimPage](
		ctx, c, c.timeout, http.MethodGet, "/v1/hostname-claims", c.access.String(), nil, query,
	)
	if err != nil {
		return nil, "", err
	}
	if len(page.Claims) > 100 {
		return nil, "", errors.New("serverclient: oversized hostname claim page")
	}
	// Strict ordering prevents duplicates and non-advancing pagination.
	previous := cursor
	for _, claim := range page.Claims {
		if !validHostnameClaimID(claim.Id) || claim.Id <= previous {
			return nil, "", errors.New("serverclient: invalid hostname claim page")
		}
		previous = claim.Id
	}
	next := ""
	if page.NextCursor != nil {
		next = *page.NextCursor
		if len(page.Claims) == 0 || next <= cursor || page.Claims[len(page.Claims)-1].Id != next {
			return nil, "", errors.New("serverclient: invalid hostname claim cursor")
		}
	}
	return page.Claims, next, nil
}

func (c *Client) ReleaseHostnameClaim(ctx context.Context, claimID string) error {
	_, err := request[struct{}](ctx, c, http.MethodDelete, hostnameClaimPath(claimID), c.access.String(), nil)
	return err
}

func (c *Client) AcquireLease(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
) (serverv1.LeaseSetup, error) {
	return request[serverv1.LeaseSetup](ctx, c, http.MethodPost, routePath(routeID, "leases"), c.access.String(), serverv1.AcquireLeaseRequest{RouteToken: routeToken.String()})
}

func (c *Client) RegisterTransport(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	endpoint transportv1.TailcatDescriptor,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "transport"), leaseToken.String(), serverv1.RegisterTransportRequest{
		Generation: int(generation),
		Endpoint: serverv1.TailcatDescriptor{
			Version:         serverv1.TailcatDescriptorVersion(endpoint.Version),
			ServerPublicKey: endpoint.ServerPublicKey,
			RelayProfile:    endpoint.RelayProfile,
		},
	})
	return err
}

func (c *Client) Ready(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "ready"), leaseToken.String(), serverv1.LeaseGenerationRequest{Generation: int(generation)})
	return err
}

func (c *Client) Heartbeat(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
) (serverv1.HeartbeatResponse, error) {
	return request[serverv1.HeartbeatResponse](ctx, c, http.MethodPost, routePath(routeID, "heartbeat"), leaseToken.String(), serverv1.LeaseGenerationRequest{Generation: int(generation)})
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	_, err := request[struct{}](ctx, c, http.MethodDelete, routePath(routeID, ""), c.access.String(), nil)
	return err
}

func (c *Client) CreateCertificateOrder(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	profile string,
	csrDER []byte,
) (serverv1.CertificateOrder, error) {
	return request[serverv1.CertificateOrder](ctx, c, http.MethodPost, "/v1/certs/orders", leaseToken.String(), serverv1.CreateCertificateOrderRequest{
		RouteId: routeID, Generation: int(generation), Profile: profile,
		Csr: base64.RawURLEncoding.EncodeToString(csrDER),
	})
}

func (c *Client) CertificateOrder(
	ctx context.Context,
	orderID string,
	leaseToken credentials.LeaseToken,
) (serverv1.CertificateOrder, error) {
	return request[serverv1.CertificateOrder](ctx, c, http.MethodGet, certificateOrderPath(orderID, ""), leaseToken.String(), nil)
}

func (c *Client) CertificateChallengeReady(
	ctx context.Context,
	orderID string,
	leaseToken credentials.LeaseToken,
) (serverv1.CertificateOrder, error) {
	return requestWithTimeout[serverv1.CertificateOrder](
		ctx, c, challengeRequestTimeout, http.MethodPost,
		certificateOrderPath(orderID, "challenge-ready"), leaseToken.String(), nil,
	)
}

func (c *Client) CertificateChallengeRemoved(
	ctx context.Context,
	orderID string,
	leaseToken credentials.LeaseToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, certificateOrderPath(orderID, "challenge-removed"), leaseToken.String(), nil)
	return err
}

func (c *Client) CertificateInstalled(
	ctx context.Context,
	routeID string,
	generation uint64,
	orderID string,
	leaseToken credentials.LeaseToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "certificate-installed"), leaseToken.String(), serverv1.CertificateInstalledRequest{
		Generation: int(generation), OrderId: orderID,
	})
	return err
}

func request[T any](
	ctx context.Context,
	client *Client,
	method, path, token string,
	requestBody any,
) (T, error) {
	return requestWithTimeout[T](ctx, client, client.timeout, method, path, token, requestBody)
}

func requestWithTimeout[T any](
	ctx context.Context,
	client *Client,
	timeout time.Duration,
	method, path, token string,
	requestBody any,
	headers ...http.Header,
) (T, error) {
	return requestWithTimeoutAndQuery[T](
		ctx, client, timeout, method, path, token, requestBody, nil, headers...,
	)
}

func requestWithTimeoutAndQuery[T any](
	ctx context.Context,
	client *Client,
	timeout time.Duration,
	method, path, token string,
	requestBody any,
	query url.Values,
	headers ...http.Header,
) (T, error) {
	var zero T
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return zero, err
		}
		body = bytes.NewReader(encoded)
	}
	endpoint := client.base.JoinPath(path)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), body)
	if err != nil {
		return zero, err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if len(headers) != 0 {
		for name, values := range headers[0] {
			request.Header[name] = append([]string(nil), values...)
		}
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	response, err := client.http.Do(request)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(payload) > maxResponseBytes {
		return zero, errors.New("serverclient: response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, responseError(response.StatusCode, response.Header, payload)
	}
	if len(payload) == 0 {
		return zero, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var result T
	if err := decoder.Decode(&result); err != nil {
		return zero, fmt.Errorf("serverclient: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return zero, errors.New("serverclient: response contains trailing JSON")
	}
	return result, nil
}

func responseError(status int, header http.Header, payload []byte) error {
	var problem serverv1.Problem
	if json.Unmarshal(payload, &problem) != nil {
		return fmt.Errorf("serverclient: HTTP %d", status)
	}
	switch problem.Code {
	case serverv1.Unauthenticated:
		return ErrUnauthenticated
	case serverv1.NotFound:
		return ErrNotFound
	case serverv1.StateConflict:
		return ErrStateConflict
	case serverv1.PreconditionFailed:
		return ErrCertificateState
	case serverv1.RateLimited:
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		seconds = min(seconds, int64((24*time.Hour)/time.Second))
		return &RateLimitError{RetryAfter: time.Duration(seconds) * time.Second}
	case serverv1.TemporarilyUnavailable:
		return ErrUnavailable
	default:
		return &ProblemError{Status: status, Problem: problem}
	}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "serverclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem serverv1.Problem
}

func (e *ProblemError) Error() string {
	return "serverclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}

func routePath(routeID, operation string) string {
	path := "/v1/routes/" + url.PathEscape(routeID)
	if strings.TrimSpace(operation) != "" {
		path += "/" + operation
	}
	return path
}

func hostnameClaimPath(claimID string) string {
	return "/v1/hostname-claims/" + url.PathEscape(claimID)
}

func validHostnameClaimID(value string) bool {
	if len(value) != len("claim_")+32 || !strings.HasPrefix(value, "claim_") {
		return false
	}
	for _, char := range value[len("claim_"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func certificateOrderPath(orderID, operation string) string {
	path := "/v1/certs/orders/" + url.PathEscape(orderID)
	if strings.TrimSpace(operation) != "" {
		path += "/" + operation
	}
	return path
}
