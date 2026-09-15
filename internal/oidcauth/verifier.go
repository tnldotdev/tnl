package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	ErrUnauthenticated = errors.New("oidcauth: unauthenticated")
	ErrUnavailable     = errors.New("oidcauth: provider unavailable")
)

// Identity is the bounded identity information authenticated by an OIDC ID token.
type Identity struct {
	Issuer          string
	Subject         string
	DisplayName     string
	NormalizedEmail string
	EmailVerified   bool
	Nonce           string
	ExpiresAt       time.Time
	AssertionDigest [32]byte
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

	mu       sync.Mutex
	provider *oidc.Provider
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
	return &providerVerifier{issuer: config.Issuer, clientID: config.ClientID, httpClient: client}, nil
}

func (v *providerVerifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > 64<<10 || strings.TrimSpace(raw) != raw {
		return Identity{}, ErrUnauthenticated
	}
	provider, err := v.getProvider(ctx)
	if err != nil {
		return Identity{}, err
	}
	return verifyToken(oidc.ClientContext(ctx, v.httpClient), provider, v.clientID, raw)
}

func (v *providerVerifier) getProvider(ctx context.Context) (*oidc.Provider, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.provider != nil {
		return v.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, v.httpClient), v.issuer)
	if err != nil {
		return nil, ErrUnavailable
	}
	v.provider = provider
	return provider, nil
}

func verifyToken(ctx context.Context, provider *oidc.Provider, clientID, raw string) (Identity, error) {
	token, err := provider.Verifier(&oidc.Config{
		ClientID: clientID, SupportedSigningAlgs: []string{"RS256"},
	}).Verify(ctx, raw)
	if err != nil {
		if providerFailure(err) {
			return Identity{}, ErrUnavailable
		}
		return Identity{}, ErrUnauthenticated
	}
	if !validClaim(token.Issuer, 2048) || !validClaim(token.Subject, 256) || token.Expiry.IsZero() {
		return Identity{}, ErrUnauthenticated
	}
	var claims struct {
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Nonce             string `json:"nonce"`
		AuthorizedParty   string `json:"azp"`
	}
	if err := token.Claims(&claims); err != nil ||
		claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID ||
		len(token.Audience) > 1 && claims.AuthorizedParty != clientID ||
		claims.Nonce != "" && !validClaim(claims.Nonce, 256) {
		return Identity{}, ErrUnauthenticated
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
	}, nil
}

func providerFailure(err error) bool {
	var networkError net.Error
	var urlError *url.Error
	return errors.As(err, &networkError) || errors.As(err, &urlError) || strings.Contains(err.Error(), "fetching keys")
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
