package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func durablePolicyAt(t *testing.T, d *Database, scope visitorscope.Scope, at time.Time) (controlv1.VisitorPolicyUpdate, error) {
	t.Helper()
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	return d.readVisitorPolicy(t.Context(), tx, scope, 0, at)
}

func TestIntegrationDurableShareUsesFullLifetimeAndCapturedAuthorityAfterSessionCleanup(t *testing.T) {
	d, connection, now := newControlStateIntegrationDatabaseWithURL(t, "durable_share")
	r := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, r, now)
	session := newOIDCSession(t, d, now)
	secret := bytes.Repeat([]byte{7}, 32)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{TeamID: url.TeamID, ActingIdentityID: r.ActingIdentityID, IdempotencyKey: "durable", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(7 * 24 * time.Hour), PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := visitortoken.ShareToken(share.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	check := func(at time.Time, want bool) visitortoken.View {
		t.Helper()
		if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, at); err != nil {
			t.Fatal(err)
		}
		body, err := durablePolicyAt(t, d, scope, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
		var issueErr error
		// exchange spends database time and signs whole-second JWT deadlines;
		// direct bearer admission must still work in the final microsecond.
		if !want || at.Before(share.ExpiresAt.Add(-time.Second)) {
			_, issueErr = d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at)
		}
		if want && (verifyErr != nil || issueErr != nil) {
			t.Fatal("original share required replacement", verifyErr, issueErr)
		}
		if !want && (!errors.Is(verifyErr, visitortoken.ErrToken) || !errors.Is(issueErr, ErrVisitorPermission)) {
			t.Fatal("projection and exchange authority diverged", verifyErr, issueErr)
		}
		if want && (len(body.Policy.ShareVerifiers) != 1 || !body.Policy.ShareVerifiers[0].ExpiresAt.Equal(share.ExpiresAt)) {
			t.Fatal("share inherited internal token lifetime")
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(token.Reveal())) || bytes.Contains(raw, []byte(source.Secret)) {
			t.Fatal("policy exposed secret")
		}
		return update.View
	}
	first := check(now, true)
	admitted, err := visitortoken.VerifyBearer(token, first, now)
	if err != nil {
		t.Fatal(err)
	}
	// cleanup is allowed to remove expired browser state, never the live share.
	if err := controlstatedb.New(d.pool).DeleteExpiredShareCookies(t.Context(), timestamptz(now.Add(6*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := controlstatedb.New(d.pool).DeleteFinishedShareHandoffs(t.Context(), timestamptz(now.Add(6*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeControlSession(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}, now); err != nil {
		t.Fatal(err)
	}
	otherRequest := r
	otherRequest.IdempotencyKey, otherRequest.CanonicalHostname, otherRequest.RequestDigest = "later", "later."+r.CanonicalHostname, sha256.Sum256([]byte("later"))
	other := createTestPublicURL(t, d, otherRequest, now)
	otherBody, err := durablePolicyAt(t, d, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: other.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	otherUpdate, err := visitorlease.Decode(otherBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(token, otherUpdate.View, now); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("share widened to later URL", err)
	}
	// a new control owner reloads only durable state; no visitor-session memory.
	reopened, err := Open(t.Context(), connection, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	d = reopened
	for _, at := range []time.Time{now.Add(6 * time.Minute), now.Add(25 * time.Hour), share.ExpiresAt.Add(-time.Microsecond)} {
		current := check(at, true)
		if err := visitortoken.CheckCurrent(admitted, current, at); err != nil {
			t.Fatal("current share lost admitted authority", err)
		}
	}
	for _, mutation := range []struct{ name, sql, restore string }{
		{"revoked share", `UPDATE control.shares SET revoked_at=$2,revoked_by_identity_id=created_by_identity_id WHERE id=$1`, `UPDATE control.shares SET revoked_at=NULL,revoked_by_identity_id=NULL WHERE id=$1`},
		{"disabled issuer", `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, `UPDATE control.identities SET disabled_at=NULL WHERE id=$1`},
		{"suspended membership", `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE identity_id=$1`, `UPDATE control.team_memberships SET manual_suspended_at=NULL WHERE identity_id=$1`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			id := r.ActingIdentityID
			if mutation.name == "revoked share" {
				id = share.ID
			}
			if _, err := d.pool.Exec(t.Context(), mutation.sql, id, now); err != nil {
				t.Fatal(err)
			}
			check(now, false)
			if _, err := d.pool.Exec(t.Context(), mutation.restore, id); err != nil {
				t.Fatal(err)
			}
			check(now, true)
		})
	}
	check(share.ExpiresAt, false)
}

func TestIntegrationDurableHTTPServiceCredentialsUseFullLifetimeAndCurrentExactGrant(t *testing.T) {
	for _, kind := range []controlv1.CreateVisitorCredentialRequestKind{"token", "share"} {
		t.Run(string(kind), func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "durable_service_"+string(kind))
			r := oidcRouteRequest(t, d, now)
			session := newOIDCSession(t, d, now)
			principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
			ctx := WithControlPrincipal(t.Context(), principal)
			service, err := d.CreateServiceAt(ctx, r.TeamID, principal.IdentityID, "durable", "durable", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
			if err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
			input := controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}, Kind: kind, ExpiresAt: now.Add(7 * 24 * time.Hour)}
			credential, err := d.CreateServiceHTTPGrant(ctx, service.ID, principal.IdentityID, input, now)
			if err != nil {
				t.Fatal(err)
			}
			if !credential.Permission.ExpiresAt.Equal(input.ExpiresAt) {
				t.Fatal("creation shortened advertised lifetime")
			}
			token := visitortoken.Token(credential.Permission.VisitorToken)
			check := func(at time.Time, want bool) visitortoken.View {
				t.Helper()
				if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, at); err != nil {
					t.Fatal(err)
				}
				body, err := durablePolicyAt(t, d, scope, at)
				if err != nil {
					t.Fatal(err)
				}
				update, err := visitorlease.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
				var issueErr error
				if !want || at.Before(input.ExpiresAt.Add(-time.Second)) {
					_, issueErr = d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, GrantTokenSource{Credential: token.Reveal()}, at)
				}
				if want && (verifyErr != nil || issueErr != nil) {
					t.Fatal("original credential required replacement", verifyErr, issueErr)
				}
				if !want && (!errors.Is(verifyErr, visitortoken.ErrToken) || !errors.Is(issueErr, ErrVisitorPermission) && !errors.Is(issueErr, ErrServiceAccess)) {
					t.Fatal("projection and exchange diverged", verifyErr, issueErr)
				}
				return update.View
			}
			first := check(now, true)
			verified, err := visitortoken.VerifyBearer(token, first, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.RevokeControlSession(ctx, principal, now); err != nil {
				t.Fatal(err)
			}
			if err := controlstatedb.New(d.pool).CleanupServiceHTTPSessions(t.Context(), timestamptz(now.Add(6*24*time.Hour))); err != nil {
				t.Fatal(err)
			}
			// another credential advances the same service's policy without revoking
			// this delegation or extending its advertised expiry.
			if _, err := d.CreateServiceHTTPGrant(t.Context(), service.ID, principal.IdentityID, input, now); err != nil {
				t.Fatal(err)
			}
			other, err := d.CreateServiceAt(t.Context(), r.TeamID, principal.IdentityID, "other", "other", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
			if err != nil {
				t.Fatal(err)
			}
			body, err := durablePolicyAt(t, d, visitorscope.Scope{Kind: visitorscope.Service, ID: other.ID}, now)
			if err != nil {
				t.Fatal(err)
			}
			update, err := visitorlease.Decode(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := visitortoken.VerifyBearer(token, update.View, now); !errors.Is(err, visitortoken.ErrToken) {
				t.Fatal("credential widened to another service", err)
			}
			for _, at := range []time.Time{now.Add(6 * time.Minute), now.Add(25 * time.Hour), input.ExpiresAt.Add(-time.Microsecond)} {
				current := check(at, true)
				if err := visitortoken.CheckCurrent(verified, current, at); err != nil {
					t.Fatal("unrelated policy change revoked delegation", err)
				}
			}
			check(input.ExpiresAt, false)
			for _, mutation := range []struct{ name, sql, restore string }{
				{"revoked credential", `UPDATE control.service_http_grants SET revoked_at=$2 WHERE service_id=$1`, `UPDATE control.service_http_grants SET revoked_at=NULL WHERE service_id=$1`},
				{"revoked grant", `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, `UPDATE control.visitor_grants SET revoked_at=NULL WHERE service_id=$1`},
				{"disabled service", `UPDATE control.services SET enabled=false WHERE id=$1 AND $2::timestamptz IS NOT NULL`, `UPDATE control.services SET enabled=true WHERE id=$1`},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					if _, err := d.pool.Exec(t.Context(), mutation.sql, service.ID, now); err != nil {
						t.Fatal(err)
					}
					check(now, false)
					if _, err := d.pool.Exec(t.Context(), mutation.restore, service.ID); err != nil {
						t.Fatal(err)
					}
					check(now, true)
				})
			}
		})
	}
}
