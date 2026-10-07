package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
