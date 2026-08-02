package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestIntegrationBuiltinAuthentication(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "builtin_authentication")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	// Preserve nanoseconds here to exercise PostgreSQL's microsecond round trip.
	now := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	type result struct {
		session ControlSession
		err     error
	}
	const callers = 4
	results := make(chan result, callers)
	for range callers {
		workers.Go(func() {
			session, err := database.CreateBuiltinControlSession(ctx, "tunnels.example.test", 7, time.Hour, 24*time.Hour, now)
			results <- result{session, err}
		})
	}
	var issued ControlSession
	for range callers {
		result := awaitIntegrationResult(t, ctx, results)
		if result.err != nil {
			t.Fatal(result.err)
		}
		if issued.SessionID != "" && result.session.Identity.Identity.ID != issued.Identity.Identity.ID {
			t.Fatal("concurrent login created different builtin identities")
		}
		issued = result.session
	}
	if issued.Identity.Identity.ID == "" || issued.Identity.PersonalTeamID == "" || len(issued.Identity.Memberships) != 1 || issued.Identity.Memberships[0].Role != "owner" {
		t.Fatalf("builtin identity context = %#v", issued.Identity)
	}
	teams, err := database.ListTeams(ctx, issued.Identity.Identity.ID)
	if err != nil || len(teams) != 1 || teams[0].ID != issued.Identity.PersonalTeamID || teams[0].DefaultDomainID == "" {
		t.Fatalf("builtin teams = %#v, %v", teams, err)
	}
	team, err := database.GetTeam(ctx, issued.Identity.Identity.ID, issued.Identity.PersonalTeamID)
	if err != nil || team != teams[0] {
		t.Fatalf("builtin team = %#v, %v", team, err)
	}
	domains, err := database.ListTeamDomains(ctx, issued.Identity.Identity.ID, team.ID)
	if err != nil || len(domains) != 1 || domains[0].CanonicalDomain != "tunnels.example.test" || domains[0].ID != team.DefaultDomainID {
		t.Fatalf("builtin domains = %#v, %v", domains, err)
	}
	principal, err := database.AuthenticateAccessToken(ctx, issued.AccessToken, 7, now)
	if err != nil || principal.IdentityID != issued.Identity.Identity.ID || !principal.Administrator {
		t.Fatalf("builtin principal = %#v, %v", principal, err)
	}
	retrySecret := principal.RetrySecret
	var ciphertext []byte
	if err := database.pool.QueryRow(ctx, `SELECT retry_secret_ciphertext FROM control.control_sessions WHERE id = $1`, principal.SessionID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, retrySecret[:]) {
		t.Fatal("control-session retry secret persisted as plaintext")
	}
	if _, err := database.AuthenticateAccessToken(ctx, issued.AccessToken, 8, now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("stale login source: %v", err)
	}
	if _, err := database.CreateBuiltinControlSession(ctx, "other.example.test", 7, time.Hour, 24*time.Hour, now); !errors.Is(err, ErrManagedDomainMismatch) {
		t.Fatalf("managed domain mismatch: %v", err)
	}
	refreshed, err := database.RefreshControlSession(ctx, issued.RefreshToken, 7, time.Hour, now.Add(time.Minute))
	if err != nil || refreshed.SessionID != issued.SessionID || !refreshed.RefreshExpiresAt.Equal(issued.RefreshExpiresAt) {
		t.Fatalf("refresh changed session identity or expiry: %v", err)
	}
	if _, err := database.AuthenticateAccessToken(ctx, issued.AccessToken, 7, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("old access token: %v", err)
	}
	if _, err := database.RefreshControlSession(ctx, issued.RefreshToken, 7, time.Hour, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("old refresh token: %v", err)
	}
	principal, err = database.AuthenticateAccessToken(ctx, refreshed.AccessToken, 7, now.Add(time.Minute))
	if err != nil || principal.RetrySecret == ([32]byte{}) || principal.RetrySecret != retrySecret {
		t.Fatalf("retry secret changed on refresh: %v", err)
	}
	if err := database.RevokeControlSession(ctx, principal, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateAccessToken(ctx, refreshed.AccessToken, 7, now.Add(2*time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("revoked access token: %v", err)
	}
	var identities, personalTeams, memberships, managedDomains int
	if err := database.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM control.identities WHERE kind = 'builtin'),
		(SELECT count(*) FROM control.teams WHERE kind = 'personal'),
		(SELECT count(*) FROM control.team_memberships),
		(SELECT count(*) FROM control.domains WHERE kind = 'managed')`).Scan(&identities, &personalTeams, &memberships, &managedDomains); err != nil {
		t.Fatal(err)
	}
	if identities != 1 || personalTeams != 1 || memberships != 1 || managedDomains != 1 {
		t.Fatalf("bootstrap rows = %d/%d/%d/%d", identities, personalTeams, memberships, managedDomains)
	}
}

func TestIntegrationExternalAuthoritySecret(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "external_authority_secret")
	const identityID = "10000000-0000-4000-8000-000000000001"
	first, err := database.EnsureExternalAuthorityPrincipal(t.Context(), identityID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.EnsureExternalAuthorityPrincipal(t.Context(), identityID, time.Now())
	if err != nil || first != second || first == ([32]byte{}) {
		t.Fatalf("external retry master key was not stable: %v", err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT external_retry_master_key_ciphertext FROM control.runtime_secrets WHERE singleton = true`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, first[:]) {
		t.Fatal("external retry master key persisted as plaintext")
	}
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
