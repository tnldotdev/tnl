// Package authorityclient is the bounded client for an authorization authority API.
package authorityclient

import (
	"bytes"
	"context"
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
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
)

const (
	maxResponseBytes      = 64 << 10
	maxOAuthTokenBytes    = 16 << 10
	defaultRequestTimeout = 20 * time.Second
)

var (
	ErrUnauthenticated = errors.New("authorityclient: unauthenticated")
	ErrNotFound        = errors.New("authorityclient: not found")
	ErrDNSProofPending = errors.New("authorityclient: DNS proof pending")
	ErrRateLimited     = errors.New("authorityclient: rate limited")
	ErrUnavailable     = errors.New("authorityclient: temporarily unavailable")
)

type Client struct {
	base    *url.URL
	http    *http.Client
	timeout time.Duration
}

type OIDCMetadata struct {
	Issuer             string
	TokenEndpoint      string
	RevocationEndpoint string
}

type OAuthTokens struct {
	SessionID        string
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

func New(endpoint string, httpClient *http.Client) (*Client, error) {
	canonical, err := clientstate.CanonicalServer(endpoint)
	if err != nil || canonical != endpoint {
		return nil, errors.New("authorityclient: endpoint must be a canonical HTTPS origin")
	}
	base, err := url.Parse(canonical)
	if err != nil {
		return nil, errors.New("authorityclient: endpoint must be a canonical HTTPS origin")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{base: base, http: httpClient, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Capabilities(ctx context.Context) (authorityv1.Capabilities, error) {
	return request[authorityv1.Capabilities](ctx, c, http.MethodGet, "/v1/capabilities", nil, nil, nil)
}

func (c *Client) AddHostname(
	ctx context.Context,
	kind authorityv1.AddHostnameRequestKind,
	name, requestKey string,
) (authorityv1.Hostname, error) {
	body := authorityv1.AddHostnameRequest{Kind: kind}
	if name != "" {
		body.Name = &name
	}
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return request[authorityv1.Hostname](ctx, c, http.MethodPost, "/v1/hostnames", body, nil, headers)
}

func (c *Client) ListHostnames(ctx context.Context) ([]authorityv1.Hostname, error) {
	var hostnames []authorityv1.Hostname
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

func (c *Client) ListHostnamesPage(ctx context.Context, cursor string) ([]authorityv1.Hostname, string, error) {
	query := make(url.Values)
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	page, err := request[authorityv1.HostnamePage](ctx, c, http.MethodGet, "/v1/hostnames", nil, query, nil)
	if err != nil {
		return nil, "", err
	}
	if len(page.Hostnames) > 100 {
		return nil, "", errors.New("authorityclient: oversized hostname page")
	}
	previous := cursor
	for _, hostname := range page.Hostnames {
		if !validID(hostname.Id, "hostname_") || hostname.Id <= previous {
			return nil, "", errors.New("authorityclient: invalid hostname page")
		}
		previous = hostname.Id
	}
	next := ""
	if page.NextCursor != nil {
		next = *page.NextCursor
		if len(page.Hostnames) == 0 || next <= cursor || page.Hostnames[len(page.Hostnames)-1].Id != next {
			return nil, "", errors.New("authorityclient: invalid hostname cursor")
		}
	}
	return page.Hostnames, next, nil
}

func (c *Client) RemoveHostname(ctx context.Context, hostnameID string) error {
	_, err := request[struct{}](ctx, c, http.MethodDelete, "/v1/hostnames/"+url.PathEscape(hostnameID), nil, nil, nil)
	return err
}

func (c *Client) CreateDomainVerification(
	ctx context.Context,
	domain, requestKey string,
) (authorityv1.DomainVerification, error) {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return request[authorityv1.DomainVerification](
		ctx, c, http.MethodPost, "/v1/domain-verifications",
		authorityv1.CreateDomainVerificationRequest{Domain: domain}, nil, headers,
	)
}

func (c *Client) DomainVerification(ctx context.Context, verificationID string) (authorityv1.DomainVerification, error) {
	return request[authorityv1.DomainVerification](
		ctx, c, http.MethodGet, domainVerificationPath(verificationID, ""), nil, nil, nil,
	)
}

func (c *Client) CompleteDomainVerification(ctx context.Context, verificationID string) (authorityv1.Hostname, error) {
	return request[authorityv1.Hostname](
		ctx, c, http.MethodPost, domainVerificationPath(verificationID, "complete"), nil, nil, nil,
	)
}

func (c *Client) IssueAuthorization(
	ctx context.Context,
	requestBody authorityv1.IssueAuthorizationRequest,
	requestKey string,
) (authorityv1.AuthorizationEnvelope, error) {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", requestKey)
	return request[authorityv1.AuthorizationEnvelope](
		ctx, c, http.MethodPost, "/v1/authorizations", requestBody, nil, headers,
	)
}

func (c *Client) DiscoverOIDC(ctx context.Context, issuer string) (OIDCMetadata, error) {
	issuerURL, err := parseHTTPSURL(issuer)
	if err != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return OIDCMetadata{}, errors.New("authorityclient: invalid OIDC issuer")
	}
	discovery := *issuerURL
	discovery.Path = strings.TrimSuffix(discovery.Path, "/") + "/.well-known/openid-configuration"
	discovery.RawPath = ""
	var document struct {
		Issuer             string `json:"issuer"`
		TokenEndpoint      string `json:"token_endpoint"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := c.requestURL(ctx, http.MethodGet, discovery.String(), nil, nil, &document, false); err != nil {
		return OIDCMetadata{}, fmt.Errorf("authorityclient: discover OIDC provider: %w", err)
	}
	if document.Issuer != issuer {
		return OIDCMetadata{}, errors.New("authorityclient: OIDC discovery issuer mismatch")
	}
	if _, err := parseHTTPSURL(document.TokenEndpoint); err != nil {
		return OIDCMetadata{}, errors.New("authorityclient: invalid OIDC token endpoint")
	}
	if document.RevocationEndpoint != "" {
		if _, err := parseHTTPSURL(document.RevocationEndpoint); err != nil {
			return OIDCMetadata{}, errors.New("authorityclient: invalid OIDC revocation endpoint")
		}
	}
	return OIDCMetadata{
		Issuer: document.Issuer, TokenEndpoint: document.TokenEndpoint,
		RevocationEndpoint: document.RevocationEndpoint,
	}, nil
}

func (c *Client) RefreshOAuth(
	ctx context.Context,
	issuer, clientID, refreshToken string,
) (OAuthTokens, error) {
	if !validOpaqueToken(refreshToken) || !validClientID(clientID) {
		return OAuthTokens{}, errors.New("authorityclient: invalid OAuth refresh request")
	}
	metadata, err := c.DiscoverOIDC(ctx, issuer)
	if err != nil {
		return OAuthTokens{}, err
	}
	form := make(url.Values)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	var response oauthTokenResponse
	started := time.Now()
	if err := c.requestURL(
		ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, &response, false,
	); err != nil {
		return OAuthTokens{}, fmt.Errorf("authorityclient: refresh OAuth token: %w", err)
	}
	return response.tokens(started, refreshToken)
}

func (c *Client) RevokeOAuth(ctx context.Context, issuer, clientID, refreshToken string) error {
	if !validOpaqueToken(refreshToken) || !validClientID(clientID) {
		return errors.New("authorityclient: invalid OAuth revocation request")
	}
	metadata, err := c.DiscoverOIDC(ctx, issuer)
	if err != nil {
		return err
	}
	if metadata.RevocationEndpoint == "" {
		return errors.New("authorityclient: OIDC provider does not advertise token revocation")
	}
	form := make(url.Values)
	form.Set("token", refreshToken)
	form.Set("token_type_hint", "refresh_token")
	form.Set("client_id", clientID)
	return c.requestURL(
		ctx, http.MethodPost, metadata.RevocationEndpoint, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, nil, false,
	)
}

type oauthTokenResponse struct {
	AccessToken           string      `json:"access_token"`
	ExpiresIn             json.Number `json:"expires_in"`
	RefreshToken          string      `json:"refresh_token"`
	RefreshExpiresIn      json.Number `json:"refresh_expires_in"`
	RefreshTokenExpiresIn json.Number `json:"refresh_token_expires_in"`
	SessionID             string      `json:"session_id"`
	TokenType             string      `json:"token_type"`
}

func (r oauthTokenResponse) tokens(started time.Time, previousRefresh string) (OAuthTokens, error) {
	seconds, err := positiveSeconds(r.ExpiresIn, 365*24*time.Hour)
	if err != nil || !validOpaqueToken(r.AccessToken) || !strings.EqualFold(r.TokenType, "Bearer") {
		return OAuthTokens{}, errors.New("authorityclient: provider returned invalid OAuth tokens")
	}
	if r.RefreshToken == "" {
		r.RefreshToken = previousRefresh
	}
	if !validOpaqueToken(r.RefreshToken) || r.SessionID != "" && !validSessionID(r.SessionID) {
		return OAuthTokens{}, errors.New("authorityclient: provider returned invalid OAuth tokens")
	}
	tokens := OAuthTokens{
		SessionID: r.SessionID, AccessToken: r.AccessToken, AccessExpiresAt: started.Add(time.Duration(seconds) * time.Second).UTC(),
		RefreshToken: r.RefreshToken,
	}
	refreshExpiry := r.RefreshExpiresIn
	if refreshExpiry == "" {
		refreshExpiry = r.RefreshTokenExpiresIn
	}
	if refreshExpiry != "" {
		refreshSeconds, err := positiveSeconds(refreshExpiry, 10*365*24*time.Hour)
		if err != nil {
			return OAuthTokens{}, errors.New("authorityclient: provider returned invalid OAuth refresh expiry")
		}
		tokens.RefreshExpiresAt = started.Add(time.Duration(refreshSeconds) * time.Second).UTC()
		if tokens.AccessExpiresAt.After(tokens.RefreshExpiresAt) {
			return OAuthTokens{}, errors.New("authorityclient: provider returned invalid OAuth token expirations")
		}
	}
	return tokens, nil
}

func request[T any](
	ctx context.Context,
	client *Client,
	method, path string,
	requestBody any,
	query url.Values,
	headers http.Header,
) (T, error) {
	var zero T
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return zero, err
		}
		body = bytes.NewReader(encoded)
		if headers == nil {
			headers = make(http.Header)
		}
		headers.Set("Content-Type", "application/json")
	}
	endpoint := client.base.JoinPath(path)
	endpoint.RawQuery = query.Encode()
	var result T
	if err := client.requestURL(ctx, method, endpoint.String(), body, headers, &result, true); err != nil {
		return zero, err
	}
	return result, nil
}

func (c *Client) requestURL(
	ctx context.Context,
	method, endpoint string,
	body io.Reader,
	headers http.Header,
	destination any,
	strict bool,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint, body)
	if err != nil {
		return err
	}
	for name, values := range headers {
		request.Header[name] = append([]string(nil), values...)
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(payload) > maxResponseBytes {
		return errors.New("authorityclient: response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response.StatusCode, response.Header, payload)
	}
	if destination == nil || len(payload) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("authorityclient: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("authorityclient: response contains trailing JSON")
	}
	return nil
}

func responseError(status int, header http.Header, payload []byte) error {
	var problem authorityv1.Problem
	if status == http.StatusTooManyRequests {
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		return &RateLimitError{RetryAfter: time.Duration(min(seconds, 86400)) * time.Second}
	}
	if status == http.StatusServiceUnavailable {
		return ErrUnavailable
	}
	if json.Unmarshal(payload, &problem) != nil {
		return fmt.Errorf("authorityclient: HTTP %d", status)
	}
	switch problem.Code {
	case authorityv1.Unauthenticated:
		return ErrUnauthenticated
	case authorityv1.NotFound:
		return ErrNotFound
	case authorityv1.PreconditionFailed:
		if strings.HasSuffix(problem.Type, "/dns-proof-pending") {
			return ErrDNSProofPending
		}
	}
	return &ProblemError{Status: status, Problem: problem}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "authorityclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem authorityv1.Problem
}

func (e *ProblemError) Error() string {
	return "authorityclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}

func domainVerificationPath(verificationID, operation string) string {
	path := "/v1/domain-verifications/" + url.PathEscape(verificationID)
	if operation != "" {
		path += "/" + operation
	}
	return path
}

func validID(value, prefix string) bool {
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func parseHTTPSURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("invalid HTTPS URL")
	}
	return parsed, nil
}

func validClientID(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value
}

func validOpaqueToken(value string) bool {
	if len(value) == 0 || len(value) > maxOAuthTokenBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validSessionID(value string) bool {
	return len(value) > 0 && len(value) <= 256 && validOpaqueToken(value)
}

func positiveSeconds(value json.Number, maximum time.Duration) (int64, error) {
	seconds, err := value.Int64()
	if err != nil || seconds <= 0 || seconds > int64(maximum/time.Second) {
		return 0, errors.New("invalid duration")
	}
	return seconds, nil
}
