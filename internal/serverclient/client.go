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
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
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
	ErrUnsupported       = errors.New("serverclient: unsupported")
)

type Client struct {
	api                    *serverv1.Client
	access                 credentials.AccessToken
	externalAuthentication bool
	timeout                time.Duration
}

// NewExternallyAuthenticated creates a client whose HTTP transport supplies authorization.
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
		return nil, errors.New("serverclient: server must be an HTTPS origin")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	apiClient, err := serverv1.NewClient(
		server,
		serverv1.WithHTTPClient(httpClient),
		serverv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Accept", "application/json, application/problem+json")
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("serverclient: configure generated client: %w", err)
	}
	return &Client{api: apiClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Capabilities(ctx context.Context) (serverv1.Capabilities, error) {
	return request[serverv1.Capabilities](ctx, c, "", c.api.GetCapabilities)
}

func (c *Client) ClientIP(ctx context.Context) (serverv1.ClientIPResponse, error) {
	return request[serverv1.ClientIPResponse](ctx, c, "", c.api.GetClientIP)
}

func (c *Client) RelayMap(ctx context.Context) ([]byte, error) {
	data, err := request[json.RawMessage](ctx, c, "", c.api.GetRelayMap)
	return []byte(data), err
}

func (c *Client) Exchange(ctx context.Context, token credentials.LoginToken) (serverv1.ControlSessionResponse, error) {
	return request[serverv1.ControlSessionResponse](ctx, c, "", func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeLoginToken(ctx, serverv1.TokenExchangeRequest{LoginToken: token.String()}, editors...)
	})
}

func (c *Client) ExchangeOIDC(ctx context.Context, token string) (serverv1.ControlSessionResponse, error) {
	return request[serverv1.ControlSessionResponse](ctx, c, "", func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeOIDCToken(ctx, serverv1.OIDCTokenExchangeRequest{IdToken: token}, editors...)
	})
}

func (c *Client) Refresh(ctx context.Context, token credentials.RefreshToken) (serverv1.ControlSessionResponse, error) {
	return request[serverv1.ControlSessionResponse](ctx, c, "", func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RefreshControlSession(ctx, serverv1.RefreshControlSessionRequest{RefreshToken: token.String()}, editors...)
	})
}

// LogoutWithAccessToken revokes the session represented by a specific saved access token.
func (c *Client) LogoutWithAccessToken(ctx context.Context, token credentials.AccessToken) error {
	_, err := request[struct{}](ctx, c, token.String(), c.api.LogoutControlSession)
	return err
}

func (c *Client) CreateRoute(ctx context.Context, requestBody serverv1.CreateRouteRequest) (serverv1.SessionSetup, error) {
	return requestWithAccess[serverv1.SessionSetup](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRoute(ctx, requestBody, editors...)
	})
}

func (c *Client) CreateRouteAuthorized(
	ctx context.Context,
	requestBody serverv1.CreateRouteRequest,
	authorization string,
) (serverv1.SessionSetup, error) {
	requestBody.SignedAuthorization = &authorization
	return request[serverv1.SessionSetup](ctx, c, "", func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRoute(ctx, requestBody, editors...)
	})
}

func (c *Client) ListRoutes(ctx context.Context) ([]serverv1.Route, error) {
	return requestWithAccess[[]serverv1.Route](ctx, c, c.api.ListRoutes)
}

func (c *Client) ClaimHostname(ctx context.Context, kind serverv1.ClaimHostnameRequestKind, label, idempotencyKey string) (serverv1.Hostname, error) {
	requestBody := serverv1.ClaimHostnameRequest{Kind: kind}
	if label != "" {
		requestBody.Label = &label
	}
	params := &serverv1.ClaimHostnameParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[serverv1.Hostname](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ClaimHostname(ctx, params, requestBody, editors...)
	})
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
	params := &serverv1.ListHostnamesParams{}
	if cursor != "" {
		params.Cursor = &cursor
	}
	page, err := requestWithAccess[serverv1.HostnamePage](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListHostnames(ctx, params, editors...)
	})
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

func (c *Client) ReleaseHostname(ctx context.Context, hostnameID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReleaseHostname(ctx, hostnameID, editors...)
	})
	return err
}

func (c *Client) CreateDomainVerification(
	ctx context.Context,
	domain, idempotencyKey string,
) (serverv1.DomainVerification, error) {
	params := &serverv1.CreateDomainVerificationParams{IdempotencyKey: idempotencyKey}
	return requestWithAccess[serverv1.DomainVerification](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateDomainVerification(ctx, params, serverv1.CreateDomainVerificationRequest{Domain: domain}, editors...)
	})
}

func (c *Client) DomainVerification(ctx context.Context, verificationID string) (serverv1.DomainVerification, error) {
	return requestWithAccess[serverv1.DomainVerification](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetDomainVerification(ctx, verificationID, editors...)
	})
}

func (c *Client) CompleteDomainVerification(ctx context.Context, verificationID string) (serverv1.Hostname, error) {
	return requestWithAccess[serverv1.Hostname](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CompleteDomainVerification(ctx, verificationID, editors...)
	})
}

func (c *Client) CreateRouteSession(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (serverv1.SessionSetup, error) {
	requestBody := serverv1.CreateRouteSessionRequest{RouteToken: routeToken.String()}
	if allowedIPPrefixes != nil {
		allowed := serverv1.AllowedIPPrefixes(allowedIPPrefixes)
		requestBody.AllowedIpPrefixes = &allowed
	}
	return requestWithAccess[serverv1.SessionSetup](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRouteSession(ctx, routeID, requestBody, editors...)
	})
}

func (c *Client) CreateRouteSessionAuthorized(
	ctx context.Context,
	routeID string,
	requestBody serverv1.CreateRouteSessionRequest,
	authorization string,
) (serverv1.SessionSetup, error) {
	requestBody.SignedAuthorization = &authorization
	return request[serverv1.SessionSetup](ctx, c, "", func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateRouteSession(ctx, routeID, requestBody, editors...)
	})
}

func (c *Client) AttachRouteTransport(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	endpoint transportv1.TailcatDescriptor,
) error {
	body := serverv1.RegisterTransportRequest{
		RouteVersion: int(version), Endpoint: serverv1.TailcatDescriptor{
			Version: serverv1.TailcatDescriptorVersion(endpoint.Version), PublisherPublicKey: endpoint.PublisherPublicKey,
			RelayRegion: endpoint.RelayRegion,
		},
	}
	_, err := request[struct{}](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RegisterRouteTransport(ctx, routeID, body, editors...)
	})
	return err
}

func (c *Client) Ready(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) error {
	_, err := request[struct{}](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkRouteReady(ctx, routeID, serverv1.RouteVersionRequest{RouteVersion: int(version)}, editors...)
	})
	return err
}

func (c *Client) Heartbeat(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) (serverv1.HeartbeatResponse, error) {
	return request[serverv1.HeartbeatResponse](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatRouteSession(ctx, routeID, serverv1.HeartbeatRouteSessionRequest{RouteVersion: int(version)}, editors...)
	})
}

func (c *Client) HeartbeatAuthorized(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	authorization string,
) (serverv1.HeartbeatResponse, error) {
	body := serverv1.HeartbeatRouteSessionRequest{RouteVersion: int(version), SignedAuthorization: &authorization}
	return request[serverv1.HeartbeatResponse](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatRouteSession(ctx, routeID, body, editors...)
	})
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteRoute(ctx, routeID, editors...)
	})
	return err
}

func (c *Client) DeleteRouteAuthorized(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
) error {
	_, err := request[struct{}](ctx, c, routeToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteRoute(ctx, routeID, editors...)
	})
	return err
}

type serverRequest func(context.Context, ...serverv1.RequestEditorFn) (*http.Response, error)

func requestWithAccess[T any](ctx context.Context, client *Client, call serverRequest) (T, error) {
	access, err := client.currentAccessToken(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	return requestWithTimeout[T](ctx, client, client.timeout, access.String(), call)
}

func (c *Client) currentAccessToken(ctx context.Context) (credentials.AccessToken, error) {
	if c.externalAuthentication {
		return "", nil
	}
	if c.access == "" {
		return "", ErrUnauthenticated
	}
	return c.access, nil
}

// ValidateControlSessionResponse validates credentials and fixed session metadata returned by the server.
func ValidateControlSessionResponse(
	response serverv1.ControlSessionResponse,
	expectedSessionID string,
	expectedRefreshExpiry time.Time,
) (clientstate.ControlSession, error) {
	access := credentials.AccessToken(response.AccessToken)
	refresh := credentials.RefreshToken(response.RefreshToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return clientstate.ControlSession{}, errors.New("serverclient: server returned an invalid access token")
	}
	if _, _, err := credentials.ParseRefreshToken(refresh); err != nil {
		return clientstate.ControlSession{}, errors.New("serverclient: server returned an invalid refresh token")
	}
	if !validControlSessionID(response.SessionId) || expectedSessionID != "" && response.SessionId != expectedSessionID ||
		!response.AccessExpiresAt.After(time.Now()) || response.RefreshExpiresAt.Before(response.AccessExpiresAt) ||
		!expectedRefreshExpiry.IsZero() && !response.RefreshExpiresAt.Equal(expectedRefreshExpiry) {
		return clientstate.ControlSession{}, errors.New("serverclient: server returned an invalid control session")
	}
	grants := make([]string, len(response.Grants))
	for index, grant := range response.Grants {
		grants[index] = string(grant)
	}
	if !validGrants(grants) {
		return clientstate.ControlSession{}, errors.New("serverclient: server returned invalid grants")
	}
	return clientstate.ControlSession{
		SessionID: response.SessionId, AccessToken: access.String(), AccessExpiresAt: response.AccessExpiresAt,
		RefreshToken: refresh.String(), RefreshExpiresAt: response.RefreshExpiresAt, Grants: grants,
	}, nil
}

func validControlSessionID(value string) bool {
	return opaqueid.Valid(value, "control_session_")
}

func validGrants(grants []string) bool {
	publish, admin := false, false
	for _, grant := range grants {
		switch grant {
		case "publish":
			if publish {
				return false
			}
			publish = true
		case "admin":
			if admin {
				return false
			}
			admin = true
		default:
			return false
		}
	}
	return publish && (len(grants) == 1 || admin && len(grants) == 2)
}

func (c *Client) CreateCertificateIssuance(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	profile string,
	csrDER []byte,
) (serverv1.CertificateIssuance, error) {
	body := serverv1.CreateCertificateIssuanceRequest{
		RouteId: routeID, RouteVersion: int(version), AcmeProfile: profile,
		Csr: base64.RawURLEncoding.EncodeToString(csrDER),
	}
	return request[serverv1.CertificateIssuance](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateCertificateIssuance(ctx, body, editors...)
	})
}

func (c *Client) CertificateChallengeReady(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	return requestWithTimeout[serverv1.CertificateIssuance](
		ctx, c, challengeRequestTimeout, sessionToken.String(),
		func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
			return c.api.MarkCertificateChallengeReady(ctx, issuanceID, editors...)
		},
	)
}

func (c *Client) CertificateChallengeRemoved(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	_, err := request[struct{}](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkCertificateChallengeRemoved(ctx, issuanceID, editors...)
	})
	return err
}

func (c *Client) CertificateInstalled(
	ctx context.Context,
	routeID string,
	version uint64,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	body := serverv1.CertificateInstalledRequest{RouteVersion: int(version), IssuanceId: issuanceID}
	_, err := request[struct{}](ctx, c, sessionToken.String(), func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkRouteCertificateInstalled(ctx, routeID, body, editors...)
	})
	return err
}

func request[T any](ctx context.Context, client *Client, token string, call serverRequest) (T, error) {
	return requestWithTimeout[T](ctx, client, client.timeout, token, call)
}

func requestWithTimeout[T any](
	ctx context.Context,
	client *Client,
	timeout time.Duration,
	token string,
	call serverRequest,
) (T, error) {
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
	case serverv1.Unsupported:
		return ErrUnsupported
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

func validHostnameID(value string) bool {
	return opaqueid.Valid(value, "hostname_")
}
