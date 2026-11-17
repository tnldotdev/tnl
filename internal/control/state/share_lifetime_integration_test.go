package state

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func ordinaryShareFixture(t *testing.T, kind string) serviceHTTPFixture {
	t.Helper()
	f := newServiceHTTPFixture(t)
	if kind == "organization" {
		team, err := f.database.CreateTeam(t.Context(), CreateTeamRequest{
			IdentityID: f.project.ActorID, IdempotencyKey: "share-team",
			RequestDigest: sha256.Sum256([]byte("share-team")), DisplayName: "shares", MemberSlug: "owner",
		}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		f.project.TeamID = team.ID
		f.service = f.local(t, "web", nil)
	}
	var storedKind string
	var required bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT kind,company_sign_in_required FROM control.teams WHERE id=$1`,
		f.project.TeamID).Scan(&storedKind, &required); err != nil || storedKind != kind || required {
		t.Fatal("fixture is not an ordinary team", storedKind, required, err)
	}
	return f
}

func shareCreatorSession(t *testing.T, f serviceHTTPFixture, access, refresh time.Duration) ControlSession {
	t.Helper()
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	session, err := f.database.createControlSession(t.Context(), controlstatedb.New(tx), f.project.ActorID, access, refresh, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return session
}

func createSessionShare(t *testing.T, f serviceHTTPFixture, parent ControlSession) (Share, []byte) {
	t.Helper()
	principal := companyTestPrincipal(t, f.database, parent, f.now)
	raw := sha256.Sum256([]byte("session-backed share secret"))
	share, err := f.database.CreateShare(WithControlPrincipal(t.Context(), principal), CreateShareRequest{
		TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID, IdempotencyKey: "session-share",
		SecretFingerprint: sha256.Sum256(raw[:]), ExpiresAt: f.now.Add(24 * time.Hour),
		ServiceIDs: []string{f.service.ID}, EntryServiceID: f.service.ID,
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var savedParent string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT control_session_id FROM control.shares WHERE id=$1`,
		share.ID).Scan(&savedParent); err != nil || savedParent != parent.SessionID {
		t.Fatal("share lost its authenticated parent", err)
	}
	return share, raw[:]
}

func assertShareSources(t *testing.T, f serviceHTTPFixture, share Share, raw []byte, cookie string, at time.Time, allowed bool) {
	t.Helper()
	sources := []VisitorTokenSource{ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(raw)}}
	if cookie != "" {
		sources = append(sources, ShareSessionTokenSource{ShareID: share.ID, Secret: cookie, RunID: f.run.RunID})
	}
	for _, source := range sources {
		_, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, source, at)
		if allowed && err != nil || !allowed && !errors.Is(err, ErrVisitorPermission) {
			t.Fatalf("%T allowed=%t at %s: %v", source, allowed, at, err)
		}
	}
}

func TestIntegrationShareLifetimeIgnoresCreatorAccessRotation(t *testing.T) {
	for _, kind := range []string{"personal", "organization"} {
		t.Run(kind, func(t *testing.T) {
			f := ordinaryShareFixture(t, kind)
			parent := shareCreatorSession(t, f, 5*time.Minute, 48*time.Hour)
			share, raw := createSessionShare(t, f, parent)
			f.run = f.publish(t, f.service)
			redeemed, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, raw, nil, f.now)
			if err != nil || !redeemed.ExpiresAt.Equal(share.ExpiresAt) {
				t.Fatal("ordinary share cookie did not retain the advertised deadline", redeemed.ExpiresAt, err)
			}
			assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, true)
			if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
				t.Fatal(err)
			}

			// cross the natural access expiry without refreshing or changing any
			// saved membership, parent expiry, revocation, or company policy.
			f.now = parent.AccessExpiresAt.Add(time.Second)
			if _, err := f.database.AuthenticateAccessToken(t.Context(), parent.AccessToken, f.now); !errors.Is(err, ErrControlAuthentication) {
				t.Fatal("expired creator access token still authenticated", err)
			}
			f.run = f.publish(t, f.service)
			assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, true)
			rotated, err := f.database.RefreshControlSession(t.Context(), parent.RefreshToken, time.Hour, f.now)
			if err != nil || rotated.SessionID != parent.SessionID || !rotated.RefreshExpiresAt.Equal(parent.RefreshExpiresAt) {
				t.Fatal("refresh changed the durable parent or fixed refresh horizon", err)
			}
			assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, true)
			fresh, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, raw, nil, f.now)
			if err != nil || !fresh.ExpiresAt.Equal(share.ExpiresAt) {
				t.Fatal("redemption after access rotation changed the share deadline", fresh.ExpiresAt, err)
			}
			var savedCookieDeadline time.Time
			digest, err := browserDigest(redeemed.CookieSecret)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.database.pool.QueryRow(t.Context(), `SELECT expires_at FROM control.share_cookies WHERE token_digest=$1`,
				digest).Scan(&savedCookieDeadline); err != nil || !savedCookieDeadline.Equal(share.ExpiresAt) {
				t.Fatal("existing redeemed cookie acquired a short access-token deadline", savedCookieDeadline, err)
			}
			// the advertised deadline remains terminal even for a live parent.
			assertShareSources(t, f, share, raw, redeemed.CookieSecret, share.ExpiresAt, false)
			if err := f.database.RevokeControlSession(t.Context(), ControlPrincipal{
				IdentityID: f.project.ActorID, SessionID: parent.SessionID,
			}, f.now); err != nil {
				t.Fatal(err)
			}
			assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, false)
			if _, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, raw, nil, f.now); err == nil {
				t.Fatal("revoked creator parent redeemed an existing share")
			}
		})
	}
}

func TestIntegrationShareLifetimeRetainsRefreshValidity(t *testing.T) {
	f := ordinaryShareFixture(t, "personal")
	parent := shareCreatorSession(t, f, 5*time.Minute, time.Hour)
	share, raw := createSessionShare(t, f, parent)
	f.run = f.publish(t, f.service)
	redeemed, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, raw, nil, f.now)
	if err != nil || !redeemed.ExpiresAt.Equal(parent.RefreshExpiresAt) {
		t.Fatal("cookie outlived the creator's fixed refresh horizon", redeemed.ExpiresAt, err)
	}
	assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, true)
	assertShareSources(t, f, share, raw, redeemed.CookieSecret, parent.RefreshExpiresAt, false)
}

func TestIntegrationShareLifetimeRetainsRequiredCompanyAuthentication(t *testing.T) {
	f := ordinaryShareFixture(t, "organization")
	f.run = f.publish(t, f.service)
	ownerSession := shareCreatorSession(t, f, time.Hour, 48*time.Hour)
	owner := companyTestPrincipal(t, f.database, ownerSession, f.now)
	connection := companyTestConnection(t, f.database, f.project.TeamID, owner, "approval", f.now)
	var required bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT company_sign_in_required FROM control.teams WHERE id=$1`,
		f.project.TeamID).Scan(&required); err != nil || !required {
		t.Fatal("company authentication fixture did not require source sign-in", err)
	}
	identity := OIDCIdentity{
		Issuer: connection.Issuer, Subject: f.project.ActorID, DisplayName: "Share creator",
		AssertionDigest: sha256.Sum256([]byte("share-company-login")),
		AssertionExpiry: f.now.Add(5 * time.Minute),
		TeamContexts: []oidc.TeamContext{{TeamID: f.project.TeamID, IdentityConnectionID: connection.ID,
			ConnectionRevision: connection.Revision, SourceID: connection.SourceID,
			Subject: "directory/" + f.project.ActorID, AuthenticatedAt: f.now.Unix()}},
	}
	bound, err := companyBindTestIntent(t, f.database, identity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := f.database.CreateOIDCControlSession(t.Context(), "tunnels.example.test", bound, 5*time.Minute, 48*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	share, raw := createSessionShare(t, f, parent)
	deadline := time.Unix(identity.TeamContexts[0].AuthenticatedAt, 0).Add(CompanyAuthenticationLifetime)
	redeemed, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, raw, nil, f.now)
	if err != nil || !redeemed.ExpiresAt.Equal(deadline) {
		t.Fatal("company share cookie changed its original authentication deadline", redeemed.ExpiresAt, deadline, err)
	}
	after := parent.AccessExpiresAt.Add(time.Second)
	assertShareSources(t, f, share, raw, "", after, true)
	rotated, err := f.database.RefreshControlSession(t.Context(), parent.RefreshToken, time.Hour, after)
	if err != nil || rotated.SessionID != parent.SessionID {
		t.Fatal("company session could not rotate within its original authentication horizon", err)
	}
	assertShareSources(t, f, share, raw, redeemed.CookieSecret, deadline, false)
	companyTestEligibility(t, f.database, connection, f.project.ActorID, 2, false, f.now)
	assertShareSources(t, f, share, raw, redeemed.CookieSecret, f.now, false)
}
