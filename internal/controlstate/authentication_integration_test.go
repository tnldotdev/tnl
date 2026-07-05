package controlstate

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestIntegrationBuiltinAuthentication(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "builtin_authentication")
	testBuiltinAuthentication(t, database)
}

func TestIntegrationExternalAuthoritySecret(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "external_authority_secret")
	testExternalAuthoritySecret(t, database)
}

func TestIntegrationOIDCAuthentication(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "oidc_authentication")
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity := OIDCIdentity{
		Issuer: "https://issuer.example", Subject: "auth0|subject", DisplayName: "Example User",
		NormalizedEmail: "user@example.com", EmailVerified: true,
		AssertionDigest: sha256.Sum256([]byte("first assertion")), AssertionExpiry: now.Add(time.Hour),
	}
	issued, err := database.CreateOIDCControlSession(
		t.Context(), "managed.example.test", identity, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Identity.Identity.Administrator || issued.Identity.Identity.DisplayName != identity.DisplayName ||
		issued.Identity.Identity.NormalizedEmail != identity.NormalizedEmail || len(issued.Identity.Memberships) != 1 ||
		issued.Identity.Memberships[0].Role != "owner" || issued.Identity.PersonalTeamID == "" {
		t.Fatalf("OIDC identity = %#v", issued.Identity)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 999, now)
	if err != nil || principal.IdentityID != issued.Identity.Identity.ID || principal.Administrator {
		t.Fatalf("OIDC principal = %#v, %v", principal, err)
	}
	refreshed, err := database.RefreshControlSession(t.Context(), issued.RefreshToken, 999, time.Hour, now.Add(time.Minute))
	if err != nil || refreshed.Identity.Identity.ID != issued.Identity.Identity.ID {
		t.Fatalf("refreshed OIDC session = %#v, %v", refreshed, err)
	}
	if _, err := database.CreateOIDCControlSession(
		t.Context(), "managed.example.test", identity, time.Hour, 24*time.Hour, now,
	); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatalf("replayed assertion error = %v", err)
	}

	identity.DisplayName = "Updated User"
	identity.AssertionDigest = sha256.Sum256([]byte("second assertion"))
	updated, err := database.CreateOIDCControlSession(
		t.Context(), "managed.example.test", identity, time.Hour, 24*time.Hour, now.Add(2*time.Minute),
	)
	if err != nil || updated.Identity.Identity.ID != issued.Identity.Identity.ID ||
		updated.Identity.Identity.DisplayName != identity.DisplayName {
		t.Fatalf("updated OIDC identity = %#v, %v", updated.Identity, err)
	}
}
