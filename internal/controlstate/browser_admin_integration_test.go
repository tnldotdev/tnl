package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationBuiltinAdministratorBrowserHandoffBindsParentAndRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "builtin_browser_handoff")
	request := builtinRouteRequest(t, database, now)
	url := createTestPublicURL(t, database, request, now)
	admin := newBuiltinSession(t, database, now)
	auth := insertBrowserTestRun(t, database, testPublishRun{
		ID: "pr_builtin_browser", PublicURLID: url.ID, TeamID: url.TeamID, MembershipID: url.MembershipID,
		ActingIdentityID: request.ActingIdentityID, CertificateCacheKey: "builtin-browser", CertificateScope: "public-url",
		CertificateIdentifiers: []string{url.CanonicalHostname}, ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	issue := func(access credentials.AccessToken, refresh credentials.RefreshToken, publicURLID string) (BrowserHandoff, string, error) {
		t.Helper()
		return database.IssueAdminBrowserHandoff(t.Context(), access, refresh, publicURLID, 7, time.Hour, 24*time.Hour, now)
	}
	otherToken, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issue(admin.AccessToken, otherToken, url.ID); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("unmatched refresh token issued handoff: %v", err)
	}
	handoff, hostname, err := issue(admin.AccessToken, admin.RefreshToken, url.ID)
	if err != nil || hostname != url.CanonicalHostname || handoff.Token == "" || handoff.PublicURLID != url.ID {
		t.Fatalf("administrator handoff = %+v, %s, %v", handoff, hostname, err)
	}
	cookie, path, _, _, _, err := database.RedeemBrowserHandoff(t.Context(), auth, handoff.Token, now)
	if err != nil || cookie == "" || path != "/" {
		t.Fatalf("redeem administrator handoff = %q, %q, %v", cookie, path, err)
	}
	access, err := database.BrowserAuthorizationForRun(t.Context(), auth, cookie, now)
	if err != nil || !access.VisitAllowed || access.Identity.IdentityID != admin.Identity.Identity.ID {
		t.Fatalf("administrator browser visit = %+v, %v", access, err)
	}
	if err := database.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: admin.SessionID, IdentityID: admin.Identity.Identity.ID}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BrowserAuthorizationForRun(t.Context(), auth, cookie, now.Add(time.Minute)); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("browser remained authorized after CLI logout: %v", err)
	}
}
