package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationSignedShareStateReadsConsumeCurrentActor(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	share, err := f.d.CreateShare(ctx, CreateShareRequest{ActingIdentityID: f.member.IdentityID,
		IdempotencyKey: "managed-share", SecretFingerprint: sha256.Sum256([]byte("share-state-secret")),
		ServiceIDs: []string{f.local.ID}, EntryServiceID: f.local.ID, ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof := managementActorProof(t, f.d, f.member.IdentityID, "share-state-read", f.now)
	signed := WithServiceActorProof(ctx, proof, proof.Nonce)
	read, err := f.d.GetShareForManagement(signed, share.ID, f.member.IdentityID, f.now)
	if err != nil || read.ID != share.ID || len(read.ServiceIDs) != 1 || read.ServiceIDs[0] != f.local.ID {
		t.Fatal("signed member owner could not read the canonical share", err)
	}
	if _, err := f.d.GetShareForManagement(signed, share.ID, f.member.IdentityID, f.now); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("managed share read did not consume its actor", err)
	}
	listProof := managementActorProof(t, f.d, f.member.IdentityID, "share-state-list", f.now)
	listed := WithServiceActorProof(ctx, listProof, listProof.Nonce)
	page, err := f.d.ListTeamShares(listed, f.team, f.member.IdentityID, "")
	if err != nil || len(page.Shares) != 1 || page.Shares[0].ID != share.ID {
		t.Fatal("signed member owner could not list the canonical share", err)
	}
	if _, err := f.d.ListTeamShares(listed, f.team, f.member.IdentityID, ""); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("share list did not consume its actor", err)
	}
	resigned := listProof
	resigned.AssertionDigest = sha256.Sum256([]byte("same-jti-resigned-for-revoke"))
	if _, err := f.d.RevokeShare(WithServiceActorProof(ctx, resigned, resigned.Nonce), share.ID, f.member.IdentityID, f.now); !errors.Is(err, ErrOIDCAssertionReplay) {
		t.Fatal("share revocation replayed a re-signed issuer JTI", err)
	}
	unrelated := managementActorProof(t, f.d, f.unrelated.IdentityID, "unrelated-share-read", f.now)
	if _, err := f.d.GetShareForManagement(WithServiceActorProof(ctx, unrelated, unrelated.Nonce), share.ID, f.unrelated.IdentityID, f.now); !errors.Is(err, ErrShareNotFound) {
		t.Fatal("another identity read a canonical share", err)
	}
	fresh := managementActorProof(t, f.d, f.member.IdentityID, "fresh-share-revoke", f.now)
	revoked, err := f.d.RevokeShare(WithServiceActorProof(ctx, fresh, fresh.Nonce), share.ID, f.member.IdentityID, f.now)
	if err != nil || revoked.ID != share.ID || revoked.RevokedAt == nil {
		t.Fatal("fresh signed revocation did not update the canonical record", err)
	}
}

func TestIntegrationSignedCompanyShareKeepsIssuerSourceWithoutControlSession(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	if _, err := f.d.pool.Exec(ctx, `UPDATE control.identities SET issuer='https://company.example',subject=id WHERE id=$1`, f.member.IdentityID); err != nil {
		t.Fatal(err)
	}
	owner := companyTestPrincipal(t, f.d, newOIDCSession(t, f.d, f.now), f.now)
	connection := companyTestConnection(t, f.d, f.team, owner, "approval", f.now)
	companyTestEligibility(t, f.d, connection, f.member.IdentityID, 1, true, f.now)
	source := oidc.TeamContext{TeamID: f.team, IdentityConnectionID: connection.ID, ConnectionRevision: connection.Revision,
		SourceID: connection.SourceID, Subject: "directory/" + f.member.IdentityID, AuthenticatedAt: f.now.Unix()}
	request := CreateShareRequest{ActingIdentityID: f.member.IdentityID, IdempotencyKey: "company-signed-share",
		ServiceIDs: []string{f.local.ID}, EntryServiceID: f.local.ID, ExpiresAt: f.now.Add(24 * time.Hour)}
	secret := sha256.Sum256([]byte("company-share-creation-secret"))
	request.SecretFingerprint = sha256.Sum256(secret[:])
	missing := managementActorProof(t, f.d, f.member.IdentityID, "company-share-no-source", f.now)
	if _, err := f.d.CreateShare(WithServiceActorProof(ctx, missing, missing.Nonce), request, f.now); !errors.Is(err, ErrServiceSourceSignInRequired) {
		t.Fatal("personal sign-in minted a required-company share", err)
	}
	proof := managementActorProof(t, f.d, f.member.IdentityID, "company-share-with-source", f.now)
	proof.TeamContexts = []oidc.TeamContext{source}
	signed := WithServiceActorProof(ctx, proof, proof.Nonce)
	share, err := f.d.CreateShare(signed, request, f.now)
	if err != nil {
		t.Fatal("current company actor could not create a canonical share", err)
	}
	var sessionless bool
	var storedContext []byte
	if err := f.d.pool.QueryRow(ctx, `SELECT control_session_id IS NULL,issuer_company_context FROM control.shares WHERE id=$1`, share.ID).Scan(&sessionless, &storedContext); err != nil || !sessionless {
		t.Fatal("signed share fabricated a control session", err)
	}
	var approved oidc.TeamContext
	if err := json.Unmarshal(storedContext, &approved); err != nil || approved != source {
		t.Fatal("share did not retain the exact approved company context", err)
	}
	later := f.now.Add(10 * time.Minute)
	retryProof := managementActorProof(t, f.d, f.member.IdentityID, "company-share-fresh-authentication", later)
	newerSource := source
	newerSource.AuthenticatedAt = later.Unix()
	retryProof.TeamContexts = []oidc.TeamContext{newerSource}
	if _, err := f.d.CreateShare(WithServiceActorProof(ctx, retryProof, retryProof.Nonce), request, later); err == nil {
		t.Fatal("exact company share retry reminted a credential")
	} else {
		var unavailable *CredentialDeliveryUnavailable
		if !errors.As(err, &unavailable) || unavailable.ResourceID != share.ID {
			t.Fatal("exact company share retry did not identify the original share", err)
		}
	}
	if err := f.d.pool.QueryRow(ctx, `SELECT issuer_company_context FROM control.shares WHERE id=$1`, share.ID).Scan(&storedContext); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(storedContext, &approved); err != nil || approved != source {
		t.Fatal("fresh source authentication slid an existing share's authentication deadline", err)
	}
	if err := f.d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.local.ID}
	credential := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret[:])}
	if _, err := f.d.IssueVisitorToken(ctx, testVisitorIssuer, scope, credential, f.now.Add(time.Minute)); err != nil {
		t.Fatal("signed-created share lost its approved company source after the request ended", err)
	}
	deadline := time.Unix(source.AuthenticatedAt, 0).Add(CompanyAuthenticationLifetime)
	if _, err := f.d.IssueVisitorToken(ctx, testVisitorIssuer, scope, credential, deadline.Add(time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share renewal extended the original company authentication deadline", err)
	}
	companyTestEligibility(t, f.d, connection, f.member.IdentityID, 2, false, f.now)
	if _, err := f.d.IssueVisitorToken(ctx, testVisitorIssuer, scope, credential, f.now.Add(time.Minute)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("offboarded company issuer retained share visitor access", err)
	}
}
