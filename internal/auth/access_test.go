package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestServiceAuthenticatesAndRevokesAccessCredentials(t *testing.T) {
	_, login, service := newTestService(t)
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	first, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := service.Authenticate(context.Background(), first.Token)
	if err != nil {
		t.Fatal(err)
	}
	if principal != localPrincipal {
		t.Fatalf("principal = %#v, want %#v", principal, localPrincipal)
	}
	if err := service.Revoke(context.Background(), principal, first.CredentialID); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(context.Background(), principal, first.CredentialID); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	if _, err := service.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked credential error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), second.Token); err != nil {
		t.Fatalf("other credential error = %v", err)
	}
}

func TestServiceHidesAccessCredentialRejectionReason(t *testing.T) {
	_, login, service := newTestService(t)
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	incorrectSecret := issued.Token.String()
	last := "A"
	if strings.HasSuffix(incorrectSecret, last) {
		last = "E"
	}
	incorrectSecret = incorrectSecret[:len(incorrectSecret)-1] + last
	for name, token := range map[string]credentials.AccessToken{
		"malformed":    "invalid",
		"wrong class":  credentials.AccessToken(login),
		"unknown":      other,
		"wrong secret": credentials.AccessToken(incorrectSecret),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("authentication error = %v", err)
			}
		})
	}

	service.now = func() time.Time { return issued.ExpiresAt }
	if _, err := service.Authenticate(context.Background(), issued.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired credential error = %v", err)
	}
}

func TestServiceHidesCredentialOwnership(t *testing.T) {
	_, login, service := newTestService(t)
	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(context.Background(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}

	for name, target := range map[string]credentials.CredentialID{
		"missing":     credentials.CredentialID(strings.Repeat("A", 22)),
		"wrong owner": issued.CredentialID,
	} {
		t.Run(name, func(t *testing.T) {
			owner := principal
			if name == "wrong owner" {
				owner.ID = "principal_other"
			}
			if err := service.Revoke(context.Background(), owner, target); !errors.Is(err, ErrCredentialNotFound) {
				t.Fatalf("revocation error = %v", err)
			}
		})
	}
	if _, err := service.Authenticate(context.Background(), issued.Token); err != nil {
		t.Fatalf("ownership probe revoked credential: %v", err)
	}
}

func TestServiceDoesNotExposeAccessTokenOnStorageFailure(t *testing.T) {
	db, login, service := newTestService(t)
	issued, err := service.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = service.Authenticate(context.Background(), issued.Token)
	if err == nil || strings.Contains(err.Error(), issued.Token.String()) {
		t.Fatalf("authentication error = %v", err)
	}
}
