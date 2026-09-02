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
	valid := ServiceConfig{
		LoginToken: "invalid", LoginTokenRevision: 1,
		AccessLifetime: DefaultAccessTokenLifetime, RefreshLifetime: DefaultRefreshTokenLifetime,
	}
	if _, err := NewService(db, valid); !errors.Is(err, credentials.ErrInvalidLoginToken) {
		t.Fatalf("invalid login configuration error = %v", err)
	}
	if _, err := NewService(nil, valid); err == nil {
		t.Fatal("nil database accepted")
	}
	valid.LoginToken = ""
	valid.OIDC = oidcVerifierFunc(func(context.Context, string) (OIDCIdentity, error) { return OIDCIdentity{}, nil })
	valid.RefreshLifetime = valid.AccessLifetime - time.Second
	if _, err := NewService(db, valid); err == nil {
		t.Fatal("refresh lifetime below access lifetime accepted")
	}
}

func TestLoginTokenControlSessionLifecycle(t *testing.T) {
	db, login, service := newTestService(t)
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	if issued.SessionID == "" || issued.AccessExpiresAt != now.Add(time.Hour) ||
		issued.RefreshExpiresAt != now.Add(30*24*time.Hour) ||
		len(issued.Grants) != 2 || issued.Grants[0] != GrantPublish || issued.Grants[1] != GrantAdmin {
		t.Fatalf("issued session = %#v", issued)
	}
	principal, err := service.Authenticate(context.Background(), issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.SessionID != issued.SessionID || principal.Identity != localIdentity ||
		!principal.HasGrant(GrantPublish) || !principal.HasGrant(GrantAdmin) {
		t.Fatalf("principal = %#v", principal)
	}
	stored, err := statedb.New(db).GetControlSession(context.Background(), issued.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AuthenticationMethod != "login_token" || stored.AuthenticationSourceRevision != 1 || stored.Grants != "publish,admin" {
		t.Fatalf("stored session = %#v", stored)
	}

	service.now = func() time.Time { return now.Add(30 * time.Minute) }
	refreshed, err := service.Refresh(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.SessionID != issued.SessionID || refreshed.AccessToken == issued.AccessToken ||
		refreshed.RefreshToken == issued.RefreshToken || refreshed.RefreshExpiresAt != issued.RefreshExpiresAt ||
		refreshed.AccessExpiresAt != now.Add(90*time.Minute) || len(refreshed.Grants) != 2 {
		t.Fatalf("refreshed session = %#v", refreshed)
	}
	if _, err := service.Authenticate(context.Background(), issued.AccessToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("replaced access token error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), refreshed.AccessToken); err != nil {
		t.Fatalf("refreshed access token: %v", err)
	}

	// Reusing the replaced refresh token revokes the session family.
	if _, err := service.Refresh(context.Background(), issued.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("replayed refresh token error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), refreshed.AccessToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("access after refresh reuse error = %v", err)
	}
}

func TestRefreshBoundsAccessToAbsoluteExpiry(t *testing.T) {
	_, login, service := newTestService(t)
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return issued.RefreshExpiresAt.Add(-30 * time.Minute) }
	refreshed, err := service.Refresh(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessExpiresAt != issued.RefreshExpiresAt || refreshed.RefreshExpiresAt != issued.RefreshExpiresAt {
		t.Fatalf("bounded expiry = %v, absolute = %v", refreshed.AccessExpiresAt, refreshed.RefreshExpiresAt)
	}
}

func TestLogoutRevokesOnlyCurrentSession(t *testing.T) {
	_, login, service := newTestService(t)
	first, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(context.Background(), first.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(context.Background(), principal); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), first.AccessToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("logged-out access error = %v", err)
	}
	if _, err := service.Refresh(context.Background(), first.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("logged-out refresh error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), second.AccessToken); err != nil {
		t.Fatalf("other session error = %v", err)
	}
}

func TestOIDCExchangePreservesReplayProtectionAndPublishGrant(t *testing.T) {
	db, err := state.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	identity := OIDCIdentity{
		Issuer: "https://account.example", Subject: "user-123",
		AssertionIdentity: "https://account.example\x00verified-nonce-1", ExpiresAt: now.Add(time.Hour),
	}
	service, err := NewService(db, ServiceConfig{
		OIDC:           oidcVerifierFunc(func(context.Context, string) (OIDCIdentity, error) { return identity, nil }),
		AccessLifetime: time.Hour, RefreshLifetime: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	issued, err := service.ExchangeOIDC(context.Background(), "id-token-serialization-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.Grants) != 1 || issued.Grants[0] != GrantPublish {
		t.Fatalf("OIDC grants = %v", issued.Grants)
	}
	principal, err := service.Authenticate(context.Background(), issued.AccessToken)
	if err != nil || !strings.HasPrefix(principal.Identity.ID, "identity_oidc_") || principal.HasGrant(GrantAdmin) {
		t.Fatalf("OIDC principal = %#v, error = %v", principal, err)
	}
	if repeated, err := service.ExchangeOIDC(context.Background(), "id-token-serialization-2"); !errors.Is(err, ErrUnauthenticated) || repeated.SessionID != "" {
		t.Fatalf("repeated OIDC exchange = %#v, error = %v", repeated, err)
	}
	identity.AssertionIdentity = "https://account.example\x00verified-nonce-2"
	if fresh, err := service.ExchangeOIDC(context.Background(), "id-token-serialization-3"); err != nil || fresh.SessionID == "" {
		t.Fatalf("fresh OIDC exchange = %#v, error = %v", fresh, err)
	}
	identity.AssertionIdentity = ""
	if empty, err := service.ExchangeOIDC(context.Background(), "id-token-serialization-4"); !errors.Is(err, ErrUnauthenticated) || empty.SessionID != "" {
		t.Fatalf("empty OIDC assertion identity exchange = %#v, error = %v", empty, err)
	}
	expiry, err := statedb.New(db).GetOIDCAssertionExpiry(context.Background())
	if err != nil || expiry != identity.ExpiresAt.UnixNano() {
		t.Fatalf("assertion expiry = %d, error = %v", expiry, err)
	}
}

func TestServiceDoesNotExposeCredentialsOnStorageFailure(t *testing.T) {
	db, login, service := newTestService(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	issued, err := service.Exchange(context.Background(), login)
	if err == nil || issued.SessionID != "" || strings.Contains(err.Error(), login.String()) {
		t.Fatalf("issued = %#v, error = %v", issued, err)
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
	service, err := NewService(db, ServiceConfig{
		LoginToken: login, LoginTokenRevision: 1,
		AccessLifetime: DefaultAccessTokenLifetime, RefreshLifetime: DefaultRefreshTokenLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, login, service
}
