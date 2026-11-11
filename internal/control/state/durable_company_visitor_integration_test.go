package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func durableCompanySession(t *testing.T, refreshLifetime time.Duration) (*Database, time.Time, Team, IdentityConnectionSecret, ControlSession) {
	t.Helper()
	d, now, owner, team := newAuthorityTeam(t)
	p := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	c := companyTestConnection(t, d, team.ID, p, "approval", now)
	source := OIDCIdentity{Issuer: c.Issuer, Subject: owner, DisplayName: "Company owner", AssertionDigest: sha256.Sum256([]byte("durable-company-session")), AssertionExpiry: now.Add(2 * time.Hour), TeamContexts: []oidc.TeamContext{{TeamID: team.ID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: "directory/" + owner, AuthenticatedAt: now.Unix()}}}
	source, err := companyBindTestIntent(t, d, source, now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", source, 5*time.Minute, refreshLifetime, now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Identity.Identity.ID != owner || !session.AccessExpiresAt.Equal(now.Add(5*time.Minute)) || !session.RefreshExpiresAt.Equal(now.Add(refreshLifetime)) {
		t.Fatal("company fixture lost exact session lifetimes")
	}
	return d, now, team, c, session
}

func TestIntegrationDurableCompanyServiceCredentialIgnoresAccessExpiryAndRotation(t *testing.T) {
	for _, fault := range []string{"company proof boundary", "session revocation", "offboarding", "connection revision", "refresh boundary"} {
		t.Run(fault, func(t *testing.T) {
			refreshLifetime := 24 * time.Hour
			if fault == "refresh boundary" {
				refreshLifetime = 30 * time.Minute
			}
			d, now, team, connection, session := durableCompanySession(t, refreshLifetime)
			principal := companyTestPrincipal(t, d, session, now)
			ctx := WithControlPrincipal(t.Context(), principal)
			service, err := d.CreateServiceAt(ctx, team.ID, principal.IdentityID, "durable-company", "durable-company", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
			if err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
			advertised := now.Add(7 * 24 * time.Hour)
			var tokens []visitortoken.Token
			for _, kind := range []controlv1.CreateVisitorCredentialRequestKind{"token", "share"} {
				grant, err := d.CreateServiceHTTPGrant(ctx, service.ID, principal.IdentityID, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}, Kind: kind, ExpiresAt: advertised}, now)
				if err != nil {
					t.Fatal(err)
				}
				if !grant.ExpiresAt.Equal(advertised) || !grant.Permission.ExpiresAt.Equal(advertised) {
					t.Fatal("internal authentication deadline replaced advertised credential lifetime")
				}
				var parent string
				if err := d.pool.QueryRow(t.Context(), `SELECT control_session_id FROM control.service_http_grants WHERE id=$1`, grant.GrantId).Scan(&parent); err != nil || parent != session.SessionID {
					t.Fatal("delegation lost exact company session provenance", err)
				}
				tokens = append(tokens, visitortoken.Token(grant.Permission.VisitorToken))
			}
			deadline := minTime(time.Unix(now.Unix(), 0).Add(CompanyAuthenticationLifetime), session.RefreshExpiresAt)
			if session.CompanyAuthenticationExpiresAt == nil || !session.CompanyAuthenticationExpiresAt.Equal(deadline) {
				t.Fatal("fixture lost explicit company proof deadline")
			}
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			check := func(at time.Time, want bool) {
				t.Helper()
				body, err := durablePolicyAt(t, d, scope, at)
				if err != nil {
					t.Fatal(err)
				}
				update, err := visitorlease.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				if want {
					if len(body.Policy.GrantVerifiers) != len(tokens) {
						t.Fatal("current delegation disappeared after access-token expiry")
					}
					for _, verifier := range body.Policy.GrantVerifiers {
						if !verifier.ExpiresAt.Equal(deadline) {
							t.Fatal("verifier did not use explicit company/refresh policy deadline")
						}
					}
				} else if len(body.Policy.GrantVerifiers) != 0 {
					t.Fatal("revoked company authority remained projected")
				}
				for _, token := range tokens {
					_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
					if want && verifyErr != nil || !want && !errors.Is(verifyErr, visitortoken.ErrToken) {
						t.Fatal("durable company bearer authority", verifyErr)
					}
					// near the boundary, direct bearer verification retains full
					// precision while an exchange spends its own database/signing time.
					if want && !at.Before(deadline.Add(-time.Second)) {
						continue
					}
					issued, issueErr := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, GrantTokenSource{Credential: token.Reveal()}, at)
					if want && (issueErr != nil || !issued.Permission.ExpiresAt.Equal(deadline.Truncate(time.Second))) || !want && !errors.Is(issueErr, ErrVisitorPermission) {
						t.Fatal("company exchange disagreed with explicit policy", issueErr)
					}
				}
			}
			check(now, true)
			at := now.Add(6 * time.Minute)
			if _, err := d.AuthenticateAccessToken(t.Context(), session.AccessToken, at); !errors.Is(err, ErrControlAuthentication) {
				t.Fatal("fixture's short access token did not expire", err)
			}
			check(at, true)
			rotated, err := d.RefreshControlSession(t.Context(), session.RefreshToken, 5*time.Minute, at)
			if err != nil {
				t.Fatal(err)
			}
			if rotated.SessionID != session.SessionID || rotated.AccessToken == session.AccessToken || rotated.RefreshToken == session.RefreshToken || !rotated.RefreshExpiresAt.Equal(session.RefreshExpiresAt) || rotated.CompanyAuthenticationExpiresAt == nil || !rotated.CompanyAuthenticationExpiresAt.Equal(deadline) {
				t.Fatal("real rotation changed fixed session or company proof lifetime")
			}
			check(at, true)
			check(now.Add(12*time.Minute), true)
			switch fault {
			case "company proof boundary", "refresh boundary":
				check(deadline.Add(-time.Microsecond), true)
				check(deadline, false)
			case "session revocation":
				if err := d.RevokeControlSession(t.Context(), principal, at); err != nil {
					t.Fatal(err)
				}
				check(at, false)
			case "offboarding":
				companyTestEligibility(t, d, connection, principal.IdentityID, 2, false, at)
				check(at, false)
			case "connection revision":
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.identity_connections SET revision=revision+1 WHERE id=$1`, connection.ID); err != nil {
					t.Fatal(err)
				}
				check(at, false)
			}
		})
	}
}

func TestIntegrationDurableCompanyPublicShareUsesEligibilityNotAccessTokenLifetime(t *testing.T) {
	d, now, team, connection, session := durableCompanySession(t, 24*time.Hour)
	principal := companyTestPrincipal(t, d, session, now)
	ctx := WithControlPrincipal(t.Context(), principal)
	domains, err := d.ListTeamDomains(ctx, principal.IdentityID, team.ID)
	if err != nil || len(domains) == 0 {
		t.Fatal("missing team domain", err)
	}
	member := session.Identity.Memberships[0]
	for _, candidate := range session.Identity.Memberships {
		if candidate.TeamID == team.ID {
			member = candidate
		}
	}
	if member.TeamID != team.ID {
		t.Fatal("missing company membership")
	}
	namespace, _ := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domains[0].CanonicalDomain, Managed: true, Mode: d.managedURLMode, TeamName: team.DisplayName, MemberSlug: member.MemberSlug, ManagedLabel: member.ManagedLabel})
	url, err := d.CreatePublicURL(ctx, CreatePublicURLRequest{TeamID: team.ID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: principal.IdentityID, IdempotencyKey: "durable-company", CanonicalHostname: "app." + namespace, Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp, DNSState: PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, 32)
	advertised := now.Add(7 * 24 * time.Hour)
	share, err := d.CreateShare(ctx, CreateShareRequest{TeamID: team.ID, ActingIdentityID: principal.IdentityID, IdempotencyKey: "durable-company", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: advertised, PolicyRevision: uint64(url.PolicyRevision), PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !share.ExpiresAt.Equal(advertised) {
		t.Fatal("share advertised internal session lifetime")
	}
	token, err := visitortoken.ShareToken(share.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	check := func(at time.Time, want bool) {
		t.Helper()
		body, err := durablePolicyAt(t, d, scope, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
		_, issueErr := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}, at)
		if want && (verifyErr != nil || issueErr != nil) || !want && (!errors.Is(verifyErr, visitortoken.ErrToken) || !errors.Is(issueErr, ErrVisitorPermission)) {
			t.Fatal("public share diverged from current eligibility policy", verifyErr, issueErr)
		}
	}
	at := now.Add(6 * time.Minute)
	check(at, true)
	if _, err := d.RefreshControlSession(t.Context(), session.RefreshToken, 5*time.Minute, at); err != nil {
		t.Fatal(err)
	}
	check(now.Add(12*time.Minute), true)
	check(time.Unix(now.Unix(), 0).Add(CompanyAuthenticationLifetime), true)
	check(now.Add(4*time.Hour), false)
	companyTestEligibility(t, d, connection, principal.IdentityID, 2, false, at)
	check(at, false)
}
