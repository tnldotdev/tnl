// Package coreclient is the bounded client for the TNL core API.
package coreclient

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

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
)

const (
	maxResponseBytes      = 64 << 10
	defaultRequestTimeout = 20 * time.Second
	// Challenge requests include core-side probing and ACME finalization.
	challengeRequestTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated  = errors.New("coreclient: unauthenticated")
	ErrStateConflict    = errors.New("coreclient: state conflict")
	ErrCertificateState = errors.New("coreclient: certificate precondition failed")
	ErrRateLimited      = errors.New("coreclient: rate limited")
	ErrUnavailable      = errors.New("coreclient: temporarily unavailable")
)

type Client struct {
	base    *url.URL
	http    *http.Client
	access  credentials.AccessToken
	timeout time.Duration
}

func New(server string, httpClient *http.Client, access credentials.AccessToken) (*Client, error) {
	base, err := url.Parse(server)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("coreclient: server must be an HTTPS origin")
	}
	if base.Path != "" && base.Path != "/" {
		return nil, errors.New("coreclient: server must not contain a path")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	base.Path = ""
	return &Client{base: base, http: httpClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Capabilities(ctx context.Context) (corev1.Capabilities, error) {
	return request[corev1.Capabilities](ctx, c, http.MethodGet, "/v1/capabilities", "", nil)
}

func (c *Client) Exchange(ctx context.Context, token credentials.BootstrapToken) (corev1.TokenExchangeResponse, error) {
	return request[corev1.TokenExchangeResponse](ctx, c, http.MethodPost, "/v1/auth/token", "", corev1.TokenExchangeRequest{
		BootstrapToken: token.String(),
	})
}

func (c *Client) CreateRoute(ctx context.Context, requestBody corev1.CreateRouteRequest) (corev1.LeaseSetup, error) {
	return request[corev1.LeaseSetup](ctx, c, http.MethodPost, "/v1/routes", c.access.String(), requestBody)
}

func (c *Client) ListRoutes(ctx context.Context) ([]corev1.Route, error) {
	return request[[]corev1.Route](ctx, c, http.MethodGet, "/v1/routes", c.access.String(), nil)
}

func (c *Client) AcquireLease(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
) (corev1.LeaseSetup, error) {
	return request[corev1.LeaseSetup](ctx, c, http.MethodPost, routePath(routeID, "leases"), c.access.String(), corev1.AcquireLeaseRequest{RouteToken: routeToken.String()})
}

func (c *Client) RegisterTransport(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	endpoint transportv1.TailcatDescriptor,
) error {
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "transport"), leaseToken.String(), corev1.RegisterTransportRequest{
		Generation: int(generation),
		Endpoint: corev1.TailcatDescriptor{
			Version:         corev1.TailcatDescriptorVersion(endpoint.Version),
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
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "ready"), leaseToken.String(), corev1.LeaseGenerationRequest{Generation: int(generation)})
	return err
}

func (c *Client) Heartbeat(
	ctx context.Context,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
) (corev1.HeartbeatResponse, error) {
	return request[corev1.HeartbeatResponse](ctx, c, http.MethodPost, routePath(routeID, "heartbeat"), leaseToken.String(), corev1.LeaseGenerationRequest{Generation: int(generation)})
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
) (corev1.CertificateOrder, error) {
	return request[corev1.CertificateOrder](ctx, c, http.MethodPost, "/v1/certs/orders", leaseToken.String(), corev1.CreateCertificateOrderRequest{
		RouteId: routeID, Generation: int(generation), Profile: profile,
		Csr: base64.RawURLEncoding.EncodeToString(csrDER),
	})
}

func (c *Client) CertificateOrder(
	ctx context.Context,
	orderID string,
	leaseToken credentials.LeaseToken,
) (corev1.CertificateOrder, error) {
	return request[corev1.CertificateOrder](ctx, c, http.MethodGet, certificateOrderPath(orderID, ""), leaseToken.String(), nil)
}

func (c *Client) CertificateChallengeReady(
	ctx context.Context,
	orderID string,
	leaseToken credentials.LeaseToken,
) (corev1.CertificateOrder, error) {
	return requestWithTimeout[corev1.CertificateOrder](
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
	_, err := request[struct{}](ctx, c, http.MethodPost, routePath(routeID, "certificate-installed"), leaseToken.String(), corev1.CertificateInstalledRequest{
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
	request, err := http.NewRequestWithContext(requestCtx, method, client.base.JoinPath(path).String(), body)
	if err != nil {
		return zero, err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
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
		return zero, errors.New("coreclient: response exceeds limit")
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
		return zero, fmt.Errorf("coreclient: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return zero, errors.New("coreclient: response contains trailing JSON")
	}
	return result, nil
}

func responseError(status int, header http.Header, payload []byte) error {
	var problem corev1.Problem
	if json.Unmarshal(payload, &problem) != nil {
		return fmt.Errorf("coreclient: HTTP %d", status)
	}
	switch problem.Code {
	case corev1.Unauthenticated:
		return ErrUnauthenticated
	case corev1.StateConflict:
		return ErrStateConflict
	case corev1.PreconditionFailed:
		return ErrCertificateState
	case corev1.RateLimited:
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		seconds = min(seconds, int64((24*time.Hour)/time.Second))
		return &RateLimitError{RetryAfter: time.Duration(seconds) * time.Second}
	case corev1.TemporarilyUnavailable:
		return ErrUnavailable
	default:
		return &ProblemError{Status: status, Problem: problem}
	}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "coreclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem corev1.Problem
}

func (e *ProblemError) Error() string {
	return "coreclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}

func routePath(routeID, operation string) string {
	path := "/v1/routes/" + url.PathEscape(routeID)
	if strings.TrimSpace(operation) != "" {
		path += "/" + operation
	}
	return path
}

func certificateOrderPath(orderID, operation string) string {
	path := "/v1/certs/orders/" + url.PathEscape(orderID)
	if strings.TrimSpace(operation) != "" {
		path += "/" + operation
	}
	return path
}
