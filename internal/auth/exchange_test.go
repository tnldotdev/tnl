package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
)

func TestNewTokenExchangeRejectsInvalidConfiguration(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := NewTokenExchange(db, "invalid"); !errors.Is(err, credentials.ErrInvalidBootstrapToken) {
		t.Fatalf("invalid bootstrap configuration error = %v", err)
	}
	if _, err := NewTokenExchange(nil, "invalid"); err == nil {
		t.Fatal("nil state database accepted")
	}
}

func TestTokenExchangeReusesLocalPrincipal(t *testing.T) {
	db, bootstrap, exchange := newTestTokenExchange(t)
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	exchange.now = func() time.Time { return now }

	first, err := exchange.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	second, err := exchange.Exchange(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token || first.CredentialID == second.CredentialID {
		t.Fatal("repeated exchange reused access credential")
	}
	if first.ExpiresAt != now.Add(AccessTokenLifetime) {
		t.Fatalf("expiry = %v, want %v", first.ExpiresAt, now.Add(AccessTokenLifetime))
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
	db, bootstrap, exchange := newTestTokenExchange(t)
	var err error
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]credentials.BootstrapToken{
		"malformed":   "invalid",
		"wrong class": credentials.BootstrapToken(access.String()),
		"rotated":     rotated,
	} {
		t.Run(name, func(t *testing.T) {
			issued, err := exchange.Exchange(context.Background(), token)
			if !errors.Is(err, ErrUnauthenticated) || issued != (IssuedAccessToken{}) {
				t.Fatalf("issued = %#v, error = %v", issued, err)
			}
		})
	}

	rotatedExchange, err := NewTokenExchange(db, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedExchange.Exchange(context.Background(), bootstrap); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old token after rotation error = %v", err)
	}
}

func TestTokenExchangeReturnsNoSecretAfterStorageFailure(t *testing.T) {
	db, bootstrap, exchange := newTestTokenExchange(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	issued, err := exchange.Exchange(context.Background(), bootstrap)
	if err == nil || issued != (IssuedAccessToken{}) {
		t.Fatalf("issued = %#v, error = %v", issued, err)
	}
	if strings.Contains(err.Error(), bootstrap.String()) {
		t.Fatal("storage error exposed bootstrap token")
	}
}

func TestTokenExchangeConcurrentFirstUse(t *testing.T) {
	db, bootstrap, exchange := newTestTokenExchange(t)
	const exchanges = 8
	errors := make(chan error, exchanges)
	for range exchanges {
		go func() {
			_, err := exchange.Exchange(context.Background(), bootstrap)
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

func newTestTokenExchange(t *testing.T) (*sql.DB, credentials.BootstrapToken, *TokenExchange) {
	t.Helper()
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := NewTokenExchange(db, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return db, bootstrap, exchange
}

func stateCounts(t *testing.T, db *sql.DB) (principals, accessCredentials int) {
	t.Helper()
	if err := db.QueryRow("SELECT COUNT(*) FROM principals").Scan(&principals); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM access_credentials").Scan(&accessCredentials); err != nil {
		t.Fatal(err)
	}
	return principals, accessCredentials
}
