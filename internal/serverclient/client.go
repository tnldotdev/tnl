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

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
)

const (
	maxResponseBytes      = 64 << 10
	defaultRequestTimeout = 20 * time.Second
	// Challenge requests include server-side probing and ACME finalization.
	challengeRequestTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated   = errors.New("serverclient: unauthenticated")
	ErrNotFound          = errors.New("serverclient: not found")
	ErrStatusConflict    = errors.New("serverclient: status conflict")
	ErrCertificateStatus = errors.New("serverclient: certificate precondition failed")
	ErrDNSProofPending   = errors.New("serverclient: DNS proof pending")
	ErrRateLimited       = errors.New("serverclient: rate limited")
	ErrUnavailable       = errors.New("serverclient: temporarily unavailable")
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

func (c *Client) CreateRoute(ctx context.Context, requestBody serverv1.CreateRouteRequest) (serverv1.SessionSetup, error) {
	return request[serverv1.SessionSetup](ctx, c, http.MethodPost, "/v1/routes", c.access.String(), requestBody)
}

func (c *Client) ListRoutes(ctx context.Context) ([]serverv1.Route, error) {
	return request[[]serverv1.Route](ctx, c, http.MethodGet, "/v1/routes", c.access.String(), nil)
}

func (c *Client) AddHostname(ctx context.Context, kind serverv1.AddHostnameRequestKind, name, requestKey string) (serverv1.Hostname, error) {
	requestBody := serverv1.AddHostnameRequest{Kind: kind}
	if name != "" {
		requestBody.Name = &name
	}
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return requestWithTimeout[serverv1.Hostname](
		ctx, c, c.timeout, http.MethodPost, "/v1/hostnames", c.access.String(), requestBody, headers,
	)
}

func (c *Client) ListHostnames(ctx context.Context) ([]serverv1.Hostname, error) {
	var hostnames []serverv1.Hostname
	cursor := ""
	for {
		page, next, err := c.ListHostnamesPage(ctx, cursor)
		if err != nil {
			return nil, err
		}
		hostnames = append(hostnames, page...)
		if next == "" {
			return hostnames, nil
		}
		cursor = next
	}
}

func (c *Client) ListHostnamesPage(
	ctx context.Context,
	cursor string,
) ([]serverv1.Hostname, string, error) {
	query := make(url.Values)
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	page, err := requestWithTimeoutAndQuery[serverv1.HostnamePage](
		ctx, c, c.timeout, http.MethodGet, "/v1/hostnames", c.access.String(), nil, query,
	)
	if err != nil {
		return nil, "", err
	}
	if len(page.Hostnames) > 100 {
		return nil, "", errors.New("serverclient: oversized hostname page")
	}
	// Strict ordering prevents duplicates and non-advancing pagination.
	previous := cursor
	for _, hostname := range page.Hostnames {
		if !validHostnameID(hostname.Id) || hostname.Id <= previous {
			return nil, "", errors.New("serverclient: invalid hostname page")
		}
		previous = hostname.Id
	}
	next := ""
	if page.NextCursor != nil {
		next = *page.NextCursor
		if len(page.Hostnames) == 0 || next <= cursor || page.Hostnames[len(page.Hostnames)-1].Id != next {
			return nil, "", errors.New("serverclient: invalid hostname cursor")
		}
	}
	return page.Hostnames, next, nil
}

func (c *Client) RemoveHostname(ctx context.Context, hostnameID string) error {
	_, err := request[struct{}](ctx, c, http.MethodDelete, hostnamePath(hostnameID), c.access.String(), nil)
	return err
}

func (c *Client) CreateDomainVerification(
	ctx context.Context,
	domain, requestKey string,
) (serverv1.DomainVerification, error) {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return requestWithTimeout[serverv1.DomainVerification](
		ctx, c, c.timeout, http.MethodPost, "/v1/domain-verifications", c.access.String(),
		serverv1.CreateDomainVerificationRequest{Domain: domain}, headers,
	)
}

func (c *Client) DomainVerification(ctx context.Context, verificationID string) (serverv1.DomainVerification, error) {
	return request[serverv1.DomainVerification](
		ctx, c, http.MethodGet, domainVerificationPath(verificationID, ""), c.access.String(), nil,
	)
}

func (c *Client) CompleteDomainVerification(ctx context.Context, verificationID string) (serverv1.Hostname, error) {
	return request[serverv1.Hostname](
		ctx, c, http.MethodPost, domainVerificationPath(verificationID, "complete"), c.access.String(), nil,
	)
}

func (c *Client) CreateRouteSession(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
) (serverv1.SessionSetup, error) {
	return request[serverv1.SessionSetup](ctx, c, http.MethodPost, routePath(routeID, "sessions"), c.access.String(), serverv1.CreateRouteSessionRequest{RouteToken: routeToken.String()})
}

func (c *Client) RegisterTransport(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	endpoint transportv1.TailcatDescriptor,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "transport"), sessionToken.String(), serverv1.RegisterTransportRequest{
		Version: int(version),
		Endpoint: serverv1.TailcatDescriptor{
			Version:            serverv1.TailcatDescriptorVersion(endpoint.Version),
			PublisherPublicKey: endpoint.PublisherPublicKey,
			RelayRegion:        endpoint.RelayRegion,
		},
	})
	return err
}

func (c *Client) Ready(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "ready"), sessionToken.String(), serverv1.RouteVersionRequest{Version: int(version)})
	return err
}

func (c *Client) Heartbeat(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) (serverv1.HeartbeatResponse, error) {
	return request[serverv1.HeartbeatResponse](ctx, c, http.MethodPost, routePath(routeID, "heartbeat"), sessionToken.String(), serverv1.RouteVersionRequest{Version: int(version)})
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	_, err := request[struct{}](ctx, c, http.MethodDelete, routePath(routeID, ""), c.access.String(), nil)
	return err
}

func (c *Client) CreateCertificateIssuance(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	profile string,
	csrDER []byte,
) (serverv1.CertificateIssuance, error) {
	return request[serverv1.CertificateIssuance](ctx, c, http.MethodPost, "/v1/certificate-issuances", sessionToken.String(), serverv1.CreateCertificateIssuanceRequest{
		RouteId: routeID, Version: int(version), AcmeProfile: profile,
		Csr: base64.RawURLEncoding.EncodeToString(csrDER),
	})
}

func (c *Client) CertificateIssuance(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	return request[serverv1.CertificateIssuance](ctx, c, http.MethodGet, certificateIssuancePath(issuanceID, ""), sessionToken.String(), nil)
}

func (c *Client) CertificateChallengeReady(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	return requestWithTimeout[serverv1.CertificateIssuance](
		ctx, c, challengeRequestTimeout, http.MethodPost,
		certificateIssuancePath(issuanceID, "challenge-ready"), sessionToken.String(), nil,
	)
}

func (c *Client) CertificateChallengeRemoved(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, certificateIssuancePath(issuanceID, "challenge-removed"), sessionToken.String(), nil)
	return err
}

func (c *Client) CertificateInstalled(
	ctx context.Context,
	routeID string,
	version uint64,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "certificate-installed"), sessionToken.String(), serverv1.CertificateInstalledRequest{
		Version: int(version), IssuanceId: issuanceID,
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
	case serverv1.StatusConflict:
		return ErrStatusConflict
	case serverv1.PreconditionFailed:
		if strings.HasSuffix(problem.Type, "/dns-proof-pending") {
			return ErrDNSProofPending
		}
		return ErrCertificateStatus
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

func hostnamePath(hostnameID string) string {
	return "/v1/hostnames/" + url.PathEscape(hostnameID)
}

func domainVerificationPath(verificationID, operation string) string {
	path := "/v1/domain-verifications/" + url.PathEscape(verificationID)
	if operation != "" {
		path += "/" + operation
	}
	return path
}

func validHostnameID(value string) bool {
	if len(value) != len("hostname_")+32 || !strings.HasPrefix(value, "hostname_") {
		return false
	}
	for _, char := range value[len("hostname_"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func certificateIssuancePath(issuanceID, operation string) string {
	path := "/v1/certificate-issuances/" + url.PathEscape(issuanceID)
	if strings.TrimSpace(operation) != "" {
		path += "/" + operation
	}
	return path
}
