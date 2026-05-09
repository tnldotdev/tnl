package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestNewServiceRejectsInvalidConfiguration(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := NewService(db, "invalid", DefaultAccessTokenLifetime); !errors.Is(err, credentials.ErrInvalidLoginToken) {
		t.Fatalf("invalid login configuration error = %v", err)
	}
	if _, err := NewService(nil, "invalid", DefaultAccessTokenLifetime); err == nil {
		t.Fatal("nil state database accepted")
	}
	if _, err := NewServiceWithOIDC(db, "", oidcVerifierFunc(func(context.Context, string) (OIDCIdentity, error) {
		return OIDCIdentity{}, nil
	}), 0); err == nil {
		t.Fatal("zero access token lifetime accepted")
	}
}

func TestTokenExchangeUsesConfiguredLifetime(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	const lifetime = 90 * time.Minute
	service, err := NewService(db, login, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	if issued.ExpiresAt != now.Add(lifetime) {
		t.Fatalf("expiry = %v, want %v", issued.ExpiresAt, now.Add(lifetime))
	}
}

func TestTokenExchangeReusesLocalPrincipal(t *testing.T) {
	db, login, exchange := newTestService(t)
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	exchange.now = func() time.Time { return now }

	first, err := exchange.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	second, err := exchange.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token || first.CredentialID == second.CredentialID {
		t.Fatal("repeated exchange reused access credential")
	}
	if first.ExpiresAt != now.Add(DefaultAccessTokenLifetime) {
		t.Fatalf("expiry = %v, want %v", first.ExpiresAt, now.Add(DefaultAccessTokenLifetime))
	}

	credentialID, hash, err := credentials.ParseAccessToken(first.Token)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := state.AuthenticateAccessCredential(context.Background(), db, credentialID, hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if principal != localPrincipal {
		t.Fatalf("principal = %#v, want %#v", principal, localPrincipal)
	}

	principals, accessCredentials := stateCounts(t, db)
	if principals != 1 || accessCredentials != 2 {
		t.Fatalf("state counts = (%d, %d), want (1, 2)", principals, accessCredentials)
	}
}

func TestTokenExchangeRejectsInvalidWrongClassAndRotatedTokens(t *testing.T) {
	db, login, exchange := newTestService(t)
	var err error
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]credentials.LoginToken{
		"malformed":   "invalid",
		"wrong class": credentials.LoginToken(access.String()),
		"rotated":     rotated,
	} {
		t.Run(name, func(t *testing.T) {
			issued, err := exchange.Exchange(context.Background(), token)
			if !errors.Is(err, ErrUnauthenticated) || issued != (IssuedAccessToken{}) {
				t.Fatalf("issued = %#v, error = %v", issued, err)
			}
		})
	}

	rotatedExchange, err := NewService(db, rotated, DefaultAccessTokenLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedExchange.Exchange(context.Background(), login); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old token after rotation error = %v", err)
	}
}

func TestTokenExchangeReturnsNoSecretAfterStorageFailure(t *testing.T) {
	db, login, exchange := newTestService(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	issued, err := exchange.Exchange(context.Background(), login)
	if err == nil || issued != (IssuedAccessToken{}) {
		t.Fatalf("issued = %#v, error = %v", issued, err)
	}
	if strings.Contains(err.Error(), login.String()) {
		t.Fatal("storage error exposed login token")
	}
}

func TestTokenExchangeConcurrentFirstUse(t *testing.T) {
	db, login, exchange := newTestService(t)
	const exchanges = 8
	errors := make(chan error, exchanges)
	for range exchanges {
		go func() {
			_, err := exchange.Exchange(context.Background(), login)
			errors <- err
		}()
	}
	for range exchanges {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}

	principals, accessCredentials := stateCounts(t, db)
	if principals != 1 || accessCredentials != exchanges {
		t.Fatalf(
			"state counts = (%d, %d), want (1, %d)",
			principals, accessCredentials, exchanges,
		)
	}
}

func TestOIDCExchangeUsesStablePrincipalAndBoundsExpiry(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	identity := OIDCIdentity{
		Issuer: "https://account.example", Subject: "user-123", ExpiresAt: now.Add(60 * 24 * time.Hour),
	}
	const lifetime = 2 * time.Hour
	service, err := NewServiceWithOIDC(db, "", oidcVerifierFunc(func(context.Context, string) (OIDCIdentity, error) {
		return identity, nil
	}), lifetime)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	issued, err := service.ExchangeOIDC(context.Background(), "id-token")
	if err != nil {
		t.Fatal(err)
	}
	if issued.ExpiresAt != now.Add(lifetime) {
		t.Fatalf("expiry = %v, want %v", issued.ExpiresAt, now.Add(lifetime))
	}
	assertionExpiresAt, err := statedb.New(db).GetOIDCAssertionExpiry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if assertionExpiresAt != identity.ExpiresAt.Unix() {
		t.Fatalf("assertion expiry = %d, want %d", assertionExpiresAt, identity.ExpiresAt.Unix())
	}
	principal, err := service.Authenticate(context.Background(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(principal.ID, "principal_oidc_") || principal.DisplayName != "" || principal.Email != "" {
		t.Fatalf("principal = %#v", principal)
	}
	if repeated, err := service.ExchangeOIDC(context.Background(), "id-token"); !errors.Is(err, ErrUnauthenticated) || repeated != (IssuedAccessToken{}) {
		t.Fatalf("repeated OIDC exchange = %#v, error = %v", repeated, err)
	}
}

func TestOIDCExchangeConsumesBearerOnceAcrossConcurrentRequests(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	service, err := NewServiceWithOIDC(db, "", oidcVerifierFunc(func(context.Context, string) (OIDCIdentity, error) {
		return OIDCIdentity{
			Issuer: "https://account.example", Subject: "user-123", ExpiresAt: now.Add(time.Hour),
		}, nil
	}), DefaultAccessTokenLifetime)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	const attempts = 8
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			_, err := service.ExchangeOIDC(context.Background(), "one-time-id-token")
			results <- err
		}()
	}
	succeeded := 0
	for range attempts {
		err := <-results
		if err == nil {
			succeeded++
			continue
		}
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("exchange error = %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful exchanges = %d, want 1", succeeded)
	}
	_, accessCredentials := stateCounts(t, db)
	if accessCredentials != 1 {
		t.Fatalf("access credentials = %d, want 1", accessCredentials)
	}
}

type oidcVerifierFunc func(context.Context, string) (OIDCIdentity, error)

func (f oidcVerifierFunc) Verify(ctx context.Context, token string) (OIDCIdentity, error) {
	return f(ctx, token)
}

func newTestService(t *testing.T) (*sql.DB, credentials.LoginToken, *Service) {
	t.Helper()
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := NewService(db, login, DefaultAccessTokenLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return db, login, exchange
}

func stateCounts(t *testing.T, db *sql.DB) (principals, accessCredentials int) {
	t.Helper()
	queries := statedb.New(db)
	principalCount, err := queries.CountPrincipals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	accessCredentialCount, err := queries.CountAccessCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return int(principalCount), int(accessCredentialCount)
}
