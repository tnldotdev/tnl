package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func applicationAccess(t *testing.T, d *Database, registered ApplicationRegistration, grant ApplicationGrant, private ed25519.PrivateKey, now time.Time) PublisherAccess {
	t.Helper()
	assertion, err := publisherproof.Sign(registered.ID, registered.KeyID, grant.ID, "https://control.example/token", private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(t.Context(), registered.ID, grant.ID, "https://control.example/token", assertion, "", now)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func TestIntegrationApplicationVisitorAuthorityUsesExactOperationAndResource(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "application_visit_scope")
	request, private := applicationRequest(t, d, now)
	registered, err := d.RegisterApplication(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	service := visitorscope.Scope{Kind: visitorscope.Service, ID: request.Grants[0].Scope.ServiceID}
	url := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: request.Grants[1].Scope.PublicURLID}
	session := newOIDCSession(t, d, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	for _, grant := range registered.Grants {
		access := applicationAccess(t, d, registered, grant, private, now)
		for _, scope := range []visitorscope.Scope{service, url} {
			issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, ApplicationTokenSource{Credential: access.Token}, now)
			allowed := grant.Operation == ApplicationVisit && (grant.Scope.ServiceID == scope.ID || grant.Scope.PublicURLID == scope.ID)
			if !allowed {
				if !errors.Is(err, ErrVisitorPermission) {
					t.Fatal("wrong operation or resource borrowed ambient visitor authority", err)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			subject, ok := issued.Permission.Subject.(visitortoken.Application)
			if !ok || subject.ClientID != registered.ID || subject.GrantID != grant.ID || subject.KeyID != registered.KeyID {
				t.Fatal("application issuance changed its exact subject")
			}
			decoded, err := visitorlease.Decode(policyObservation(t, d, scope, 0))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := visitortoken.VerifyBearer(issued.Token, decoded.View, time.Now()); err != nil {
				t.Fatal("issuance disagreed with current application projection", err)
			}
		}
	}
	// the machine key remains its own authority after the setup session ends.
	if err := d.RevokeControlSession(ctx, ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}, now); err != nil {
		t.Fatal(err)
	}
	access := applicationAccess(t, d, registered, registered.Grants[0], private, now)
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, service, ApplicationTokenSource{Credential: access.Token}, now); err != nil {
		t.Fatal("application borrowed the creator's short-lived control session", err)
	}
	for _, token := range []string{"", "pta_" + strings.Repeat("A", 43), string(session.AccessToken)} {
		if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, url, ApplicationTokenSource{Credential: token}, now); !errors.Is(err, ErrVisitorPermission) {
			t.Fatal("invalid explicit application credential fell back to a human source", err)
		}
	}
}

func TestIntegrationApplicationVisitorRevocationRotationAndShortenedExpiry(t *testing.T) {
	for _, fault := range []string{"grant", "identity", "membership", "key", "expiry"} {
		t.Run(fault, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "application_visit_"+fault)
			request, private := applicationRequest(t, d, now)
			registered, err := d.RegisterApplication(t.Context(), request, now)
			if err != nil {
				t.Fatal(err)
			}
			grant := registered.Grants[3]
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: grant.Scope.PublicURLID}
			access := applicationAccess(t, d, registered, grant, private, now)
			source := ApplicationTokenSource{Credential: access.Token}
			issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "grant":
				err = d.RevokePublisherGrant(t.Context(), request.TeamID, registered.ID, grant.ID, request.ActingIdentityID, now)
			case "identity":
				err = d.RevokePublisherIdentity(t.Context(), request.TeamID, registered.ID, request.ActingIdentityID, now)
			case "membership":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE team_id=$1`, request.TeamID, now)
			case "expiry":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, grant.ID, now.Add(3*time.Second))
			case "key":
				publisher := applicationAccess(t, d, registered, registered.Grants[1], private, now)
				public, replacement, generateErr := ed25519.GenerateKey(rand.Reader)
				if generateErr != nil {
					t.Fatal(generateErr)
				}
				keyID := "pkey_" + strings.Repeat("Z", 22)
				audience := "https://control.example/rotate"
				proof, signErr := publisherproof.Sign(registered.ID, keyID, publisher.GrantID, audience, replacement, now)
				if signErr != nil {
					t.Fatal(signErr)
				}
				current, signErr := publisherproof.Sign(registered.ID, registered.KeyID, publisher.GrantID, publisherproof.RotationAudience(audience, keyID, public), private, now)
				if signErr != nil {
					t.Fatal(signErr)
				}
				err = d.RotatePublisherKey(t.Context(), publisher.Token, "", keyID, audience, public, proof, current, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			body := policyObservation(t, d, scope, 0)
			decoded, err := visitorlease.Decode(body)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now()
			if fault == "expiry" {
				at = now.Add(3 * time.Second)
			}
			if _, err := visitortoken.VerifyBearer(issued.Token, decoded.View, at); err == nil {
				t.Fatal("application admission ignored current parent mutation")
			}
			if fault == "expiry" {
				short, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
				if err != nil || !short.Permission.ExpiresAt.Equal(now.Add(3*time.Second).Truncate(time.Second)) {
					t.Fatal("issuance widened a shortened application grant", err)
				}
			} else if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
				t.Fatal("revoked or replaced application authority issued new permission", err)
			}
		})
	}
}

func TestIntegrationApplicationVisitorProjectionCapacityIsBoundedAtCreation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "application_visit_capacity")
	request, _ := applicationRequest(t, d, now)
	request.Grants = request.Grants[:1]
	var first ApplicationRegistration
	for index := range 256 {
		request.IdempotencyKey = fmt.Sprintf("app-%d", index)
		registered, err := d.RegisterApplication(t.Context(), request, now)
		if err != nil {
			t.Fatal("bounded registration failed", index, err)
		}
		if index == 0 {
			first = registered
		}
	}
	request.IdempotencyKey = "overflow"
	if _, err := d.RegisterApplication(t.Context(), request, now); !errors.Is(err, ErrApplicationRegistration) {
		t.Fatal("creation overflowed authenticated visitor projection", err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: request.Grants[0].Scope.ServiceID}
	body := policyObservation(t, d, scope, 0)
	if len(body.Policy.ApplicationLeases) != 256 {
		t.Fatal("maximum policy truncated application grants")
	}
	if _, err := visitorlease.Decode(body); err != nil {
		t.Fatal("maximum live application policy could not be consumed", err)
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 2<<20 {
		t.Fatal("bounded application grants overflowed policy HTTP budget", err)
	}
	// dormant member grants still count, because membership restoration can make
	// them live again without another registration transaction.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE team_id=$1`, request.TeamID, now); err != nil {
		t.Fatal(err)
	}
	if len(policyObservation(t, d, scope, 0).Policy.ApplicationLeases) != 0 {
		t.Fatal("dormant member applications remained authorized")
	}
	count, err := controlstatedb.New(d.pool).CountApplicationVisitGrants(t.Context(), controlstatedb.CountApplicationVisitGrantsParams{Kind: "service", ResourceID: scope.ID, Now: timestamptz(now)})
	if err != nil || count != 256 {
		t.Fatal("dormant grants released capacity that restoration could overflow", count, err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=NULL WHERE team_id=$1`, request.TeamID); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokePublisherIdentity(t.Context(), request.TeamID, first.ID, request.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RegisterApplication(t.Context(), request, now); err != nil {
		t.Fatal("revoked identity did not release projection capacity", err)
	}
}

func TestIntegrationApplicationVisitorMembershipAndTeamDelegationStayDistinct(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "application", "application", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := RegisterApplicationRequest{TeamID: team.ID, ActingIdentityID: owner, Name: "company-app", Ownership: "member", IdempotencyKey: "member-app", PublicKey: public, Grants: []ApplicationGrantRequest{{Operation: ApplicationVisit, Scope: PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}}}}
	memberApp, err := d.RegisterApplication(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	request.Ownership, request.IdempotencyKey = "team", "team-app"
	teamApp, err := d.RegisterApplication(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	memberAccess := applicationAccess(t, d, memberApp, memberApp.Grants[0], private, now)
	teamAccess := applicationAccess(t, d, teamApp, teamApp.Grants[0], private, now)
	principal := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	connection := companyTestConnection(t, d, team.ID, principal, "approval", now)
	deadline := now.Add(3 * time.Second)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.company_eligibility SET valid_until=$2 WHERE identity_connection_id=$1`, connection.ID, deadline); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	memberToken, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ApplicationTokenSource{Credential: memberAccess.Token}, now)
	if err != nil || !memberToken.Permission.ExpiresAt.Equal(deadline.Truncate(time.Second)) {
		t.Fatal("member application ignored current company eligibility deadline", err)
	}
	teamToken, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ApplicationTokenSource{Credential: teamAccess.Token}, now)
	if err != nil || !teamToken.Permission.ExpiresAt.After(deadline) {
		t.Fatal("team delegation borrowed its creator's company session", err)
	}
	decoded, err := visitorlease.Decode(policyObservation(t, d, scope, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(memberToken.Token, decoded.View, deadline); err == nil {
		t.Fatal("member application remained live after company eligibility expired")
	}
	if _, err := visitortoken.VerifyBearer(teamToken.Token, decoded.View, deadline); err != nil {
		t.Fatal("team application lost independently delegated authority", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ApplicationTokenSource{Credential: memberAccess.Token}, deadline); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("expired eligibility minted member application access", err)
	}
}

func TestIntegrationApplicationVisitorSnapshotCannotIssueAfterKeyRetirement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "application_visit_key_snapshot")
	request, private := applicationRequest(t, d, now)
	registered, err := d.RegisterApplication(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	access := applicationAccess(t, d, registered, registered.Grants[3], private, now)
	publisher := applicationAccess(t, d, registered, registered.Grants[1], private, now)
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var keyID string
	if err := tx.QueryRow(t.Context(), `SELECT id FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND retired_at IS NULL`, registered.ID).Scan(&keyID); err != nil || keyID != registered.KeyID {
		t.Fatal("snapshot was not established on the original key", err)
	}
	public, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacementID := "pkey_" + strings.Repeat("Q", 22)
	audience := "https://control.example/rotate"
	proof, err := publisherproof.Sign(registered.ID, replacementID, publisher.GrantID, audience, replacement, now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := publisherproof.Sign(registered.ID, registered.KeyID, publisher.GrantID, publisherproof.RotationAudience(audience, replacementID, public), private, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RotatePublisherKey(t.Context(), publisher.Token, "", replacementID, audience, public, proof, current, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: registered.Grants[3].Scope.PublicURLID}
	_, err = d.issueVisitorToken(t.Context(), tx, testVisitorIssuer, scope, ApplicationTokenSource{Credential: access.Token}, newAuthorizationClock(now))
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		t.Fatal("stale key snapshot did not force whole-transaction retry", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ApplicationTokenSource{Credential: access.Token}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("fresh issuance reused retired key authority", err)
	}
	registered.KeyID = replacementID
	refreshed := applicationAccess(t, d, registered, registered.Grants[3], replacement, now)
	issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ApplicationTokenSource{Credential: refreshed.Token}, now)
	if err != nil {
		t.Fatal("replacement application key could not issue visit permission", err)
	}
	decoded, err := visitorlease.Decode(policyObservation(t, d, scope, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(issued.Token, decoded.View, time.Now()); err != nil {
		t.Fatal("replacement key was absent from authenticated policy", err)
	}
}
