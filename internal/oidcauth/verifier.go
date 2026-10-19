package oidcauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tnldotdev/tnl/internal/httpclient"
)

var (
	ErrUnauthenticated = errors.New("oidcauth: unauthenticated")
	ErrUnavailable     = errors.New("oidcauth: provider unavailable")
)

// Identity contains the limited identity fields authenticated by an OIDC ID token.
type Identity struct {
	Issuer                 string
	Subject                string
	DisplayName            string
	NormalizedEmail        string
	EmailVerified          bool
	Nonce                  string
	ExpiresAt              time.Time
	AssertionDigest        [32]byte
	ClientID               string
	IssuedAt               time.Time
	TeamContexts           []TeamContext
	AuthenticatedAt        time.Time
	TenantID, HostedDomain string
	Groups                 []string
}

// TeamContext is issuer-signed company authentication, not directory membership.
// control binds it to its exact connection revision, eligibility and new session.
type TeamContext struct {
	TeamID               string `json:"team_id"`
	IdentityConnectionID string `json:"identity_connection_id"`
	ConnectionRevision   int64  `json:"connection_revision"`
	Subject              string `json:"subject"`
	SourceID             string `json:"source_id"`
	AuthenticatedAt      int64  `json:"authenticated_at"`
}

// Verifier verifies ID tokens from one exact OIDC issuer for one client.
type Verifier interface {
	Verify(context.Context, string) (Identity, error)
}

type VerifierConfig struct {
	Issuer     string
	ClientID   string
	HTTPClient *http.Client
}

type providerVerifier struct {
	issuer     string
	clientID   string
	httpClient *http.Client

	discovery chan struct{}
	provider  *oidc.Provider
	keySet    oidc.KeySet
}

// NewVerifier validates configuration without contacting the provider.
func NewVerifier(config VerifierConfig) (Verifier, error) {
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("oidcauth: issuer must be an HTTPS URL without credentials, query, or fragment")
	}
	if !validClaim(config.ClientID, 128) {
		return nil, errors.New("oidcauth: client ID is invalid")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	client = httpclient.NoRedirects(client)
	if client.Timeout <= 0 || client.Timeout > 20*time.Second {
		client.Timeout = 20 * time.Second
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = boundedProviderTransport{base}
	return &providerVerifier{
		issuer: config.Issuer, clientID: config.ClientID, httpClient: client,
		discovery: make(chan struct{}, 1),
	}, nil
}

func (v *providerVerifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > 64<<10 || strings.TrimSpace(raw) != raw {
		return Identity{}, ErrUnauthenticated
	}
	provider, err := v.getProvider(ctx)
	if err != nil {
		return Identity{}, err
	}
	return verifyToken(oidc.ClientContext(ctx, v.httpClient), provider, v.clientID, raw, v.keySet)
}

func (v *providerVerifier) getProvider(ctx context.Context) (*oidc.Provider, error) {
	select {
	case v.discovery <- struct{}{}:
		defer func() { <-v.discovery }()
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if v.provider != nil {
		return v.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, v.httpClient), v.issuer)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	keySet, err := providerKeySet(oidc.ClientContext(ctx, v.httpClient), provider)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	v.provider, v.keySet = provider, keySet
	return provider, nil
}

func verifyToken(ctx context.Context, provider *oidc.Provider, clientID, raw string, keySets ...oidc.KeySet) (Identity, error) {
	var keySet oidc.KeySet
	if len(keySets) != 0 {
		keySet = keySets[0]
	} else {
		var err error
		keySet, err = providerKeySet(ctx, provider)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
	}
	observed := &observedKeySet{KeySet: keySet}
	token, err := oidc.NewVerifier(providerIssuer(provider), observed, &oidc.Config{
		ClientID: clientID, SupportedSigningAlgs: []string{"RS256"},
	}).Verify(ctx, raw)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return Identity{}, cause
		}
		var fetchFailure *keyFetchError
		if errors.As(observed.err, &fetchFailure) {
			return Identity{}, fmt.Errorf("%w: %w", ErrUnavailable, observed.err)
		}
		return Identity{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if token.Issuer != providerIssuer(provider) || !validClaim(token.Issuer, 2048) || !validClaim(token.Subject, 256) || token.Expiry.IsZero() {
		return Identity{}, ErrUnauthenticated
	}
	var claims struct {
		Name              string        `json:"name"`
		PreferredUsername string        `json:"preferred_username"`
		Email             string        `json:"email"`
		EmailVerified     bool          `json:"email_verified"`
		Nonce             string        `json:"nonce"`
		AuthorizedParty   string        `json:"azp"`
		IssuedAt          int64         `json:"iat"`
		NotBefore         int64         `json:"nbf"`
		TeamContexts      []TeamContext `json:"tnl_team_contexts"`
		AuthenticatedAt   int64         `json:"auth_time"`
		TenantID          string        `json:"tid"`
		HostedDomain      string        `json:"hd"`
		Groups            []string      `json:"groups"`
	}
	if err := token.Claims(&claims); err != nil ||
		claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID ||
		len(token.Audience) > 1 && claims.AuthorizedParty != clientID ||
		claims.Nonce != "" && !validClaim(claims.Nonce, 256) {
		return Identity{}, ErrUnauthenticated
	}
	now := time.Now()
	if claims.AuthenticatedAt > now.Add(time.Minute).Unix() || len(claims.Groups) > 1024 || len(claims.TenantID) > 256 || len(claims.HostedDomain) > 256 {
		return Identity{}, ErrUnauthenticated
	}
	for _, group := range claims.Groups {
		if !validClaim(group, 256) {
			return Identity{}, ErrUnauthenticated
		}
	}
	if claims.IssuedAt <= 0 || claims.IssuedAt > now.Add(time.Minute).Unix() || claims.NotBefore > now.Add(time.Minute).Unix() || token.Expiry.Unix() <= claims.IssuedAt || token.Expiry.Sub(time.Unix(claims.IssuedAt, 0)) > 24*time.Hour || len(token.Audience) > 16 {
		return Identity{}, ErrUnauthenticated
	}
	if len(claims.TeamContexts) > 64 {
		return Identity{}, ErrUnauthenticated
	}
	seen := make(map[string]bool, len(claims.TeamContexts))
	for _, c := range claims.TeamContexts {
		key := c.TeamID + "/" + c.IdentityConnectionID
		if !validClaim(c.TeamID, 128) || !validClaim(c.IdentityConnectionID, 128) || !validClaim(c.Subject, 256) || !validClaim(c.SourceID, 256) || c.ConnectionRevision < 1 || c.AuthenticatedAt <= 0 || seen[key] {
			return Identity{}, ErrUnauthenticated
		}
		seen[key] = true
	}

	email := ""
	if claims.EmailVerified {
		email = strings.ToLower(strings.TrimSpace(claims.Email))
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email || len(email) > 320 {
			return Identity{}, ErrUnauthenticated
		}
	}
	displayName := firstValidClaim(256, claims.Name, claims.PreferredUsername, email, token.Subject)
	if displayName == "" {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{
		Issuer: token.Issuer, Subject: token.Subject, DisplayName: displayName,
		NormalizedEmail: email, EmailVerified: claims.EmailVerified, Nonce: claims.Nonce,
		ExpiresAt: token.Expiry.UTC(), AssertionDigest: sha256.Sum256([]byte(raw)),
		TeamContexts:    claims.TeamContexts,
		ClientID:        clientID,
		IssuedAt:        time.Unix(claims.IssuedAt, 0),
		AuthenticatedAt: time.Unix(claims.AuthenticatedAt, 0), TenantID: claims.TenantID, HostedDomain: claims.HostedDomain, Groups: claims.Groups,
	}, nil
}

type boundedProviderTransport struct{ base http.RoundTripper }

func (t boundedProviderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	const maximum = 256 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maximum {
		return nil, errors.New("OIDC response exceeds size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func firstValidClaim(maximum int, values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if validClaim(value, maximum) {
			return value
		}
	}
	return ""
}

func validClaim(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
