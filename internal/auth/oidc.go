package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrOIDCUnavailable = errors.New("auth: OIDC provider unavailable")

type OIDCIdentity struct {
	Issuer    string
	Subject   string
	ExpiresAt time.Time
}

type OIDCVerifier interface {
	Verify(context.Context, string) (OIDCIdentity, error)
}

type OIDCConfig struct {
	Issuer     string
	ClientID   string
	HTTPClient *http.Client
}

type oidcVerifier struct {
	issuer     string
	clientID   string
	httpClient *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier validates local configuration without contacting the provider.
func NewOIDCVerifier(config OIDCConfig) (OIDCVerifier, error) {
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.Path != "" && issuer.Path != "/" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("auth: OIDC issuer must be an HTTPS origin")
	}
	if strings.TrimSpace(config.ClientID) != config.ClientID || config.ClientID == "" || len(config.ClientID) > 128 {
		return nil, errors.New("auth: OIDC client ID is invalid")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &oidcVerifier{
		issuer:     strings.TrimSuffix(issuer.String(), "/"),
		clientID:   config.ClientID,
		httpClient: client,
	}, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, raw string) (OIDCIdentity, error) {
	verifier, err := v.idTokenVerifier(ctx)
	if err != nil {
		return OIDCIdentity{}, err
	}
	token, err := verifier.Verify(oidc.ClientContext(ctx, v.httpClient), raw)
	if err != nil {
		var networkError net.Error
		var urlError *url.Error
		if errors.As(err, &networkError) || errors.As(err, &urlError) || strings.Contains(err.Error(), "fetching keys") {
			return OIDCIdentity{}, ErrOIDCUnavailable
		}
		return OIDCIdentity{}, ErrUnauthenticated
	}
	if strings.TrimSpace(token.Subject) == "" || len(token.Subject) > 256 || !token.Expiry.After(time.Now()) {
		return OIDCIdentity{}, ErrUnauthenticated
	}
	return OIDCIdentity{Issuer: token.Issuer, Subject: token.Subject, ExpiresAt: token.Expiry.UTC()}, nil
}

func (v *oidcVerifier) idTokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, v.httpClient), v.issuer)
	if err != nil {
		return nil, ErrOIDCUnavailable
	}
	v.verifier = provider.Verifier(&oidc.Config{
		ClientID:             v.clientID,
		SupportedSigningAlgs: []string{"RS256"},
	})
	return v.verifier, nil
}
