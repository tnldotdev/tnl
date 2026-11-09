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
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sharePolicyAt(t *testing.T, d *Database, scope visitorscope.Scope, at time.Time) (controlv1.VisitorPolicyUpdate, error) {
	t.Helper()
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	return d.readVisitorPolicy(t.Context(), tx, scope, 0, at)
}

func TestIntegrationVisitorShareVerifiersUseCurrentAuthorityForExactCapturedResources(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_share_verifiers")
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	otherRequest := request
	otherRequest.IdempotencyKey = "other"
	otherRequest.CanonicalHostname = "other." + request.CanonicalHostname
	otherRequest.RequestDigest = sha256.Sum256([]byte("other"))
	other := createTestPublicURL(t, d, otherRequest, now)
	secret := bytes.Repeat([]byte{5}, 32)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{TeamID: url.TeamID, ActingIdentityID: request.ActingIdentityID, IdempotencyKey: "durable", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(7 * 24 * time.Hour), PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}}}, now)
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
		body, err := sharePolicyAt(t, d, scope, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
		_, issueErr := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at)
		if want && (verifyErr != nil || issueErr != nil) {
			t.Fatal("current live-share rule denied access", verifyErr, issueErr)
		}
		if !want && (!errors.Is(verifyErr, visitortoken.ErrToken) || !errors.Is(issueErr, ErrVisitorPermission)) {
			t.Fatal("projection and source authorization diverged", verifyErr, issueErr)
		}
		if want && (len(body.Policy.ShareVerifiers) != 1 || !body.Policy.ShareVerifiers[0].ExpiresAt.Equal(share.ExpiresAt)) {
			t.Fatal("share lifetime was shortened to a prepared token lifetime")
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(token.Reveal())) || bytes.Contains(raw, []byte(source.Secret)) {
			t.Fatal("policy exposed a share secret")
		}
		return update.View
	}
	first := check(now, true)
	admitted, err := visitortoken.VerifyBearer(token, first, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, url.ID); err != nil {
		t.Fatal(err)
	}
	next := check(now.Add(6*24*time.Hour), true)
	if err := visitortoken.CheckCurrent(admitted, next, now.Add(6*24*time.Hour)); err != nil {
		t.Fatal("unrelated revision canceled an admitted share", err)
	}
	otherBody, err := sharePolicyAt(t, d, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: other.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	otherUpdate, err := visitorlease.Decode(otherBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherBody.Policy.ShareVerifiers) != 0 {
		t.Fatal("share expanded to a later URL")
	}
	if _, err := visitortoken.VerifyBearer(token, otherUpdate.View, now); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("wrong URL accepted credential", err)
	}
	for _, mutation := range []struct{ name, sql, restore string }{
		{"revoked", `UPDATE control.shares SET revoked_at=$2,revoked_by_identity_id=created_by_identity_id WHERE id=$1`, `UPDATE control.shares SET revoked_at=NULL,revoked_by_identity_id=NULL WHERE id=$1`},
		{"disabled issuer", `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, `UPDATE control.identities SET disabled_at=NULL WHERE id=$1`},
		{"suspended membership", `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE identity_id=$1`, `UPDATE control.team_memberships SET manual_suspended_at=NULL WHERE identity_id=$1`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			id := request.ActingIdentityID
			if mutation.name == "revoked" {
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

func TestIntegrationVisitorShareVerifierProjectionIsBoundedWithoutTruncation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_share_bounds")
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	_, err := d.pool.Exec(t.Context(), `WITH inserted AS (
	    INSERT INTO control.shares(id,team_id,scope,created_by_identity_id,idempotency_key,request_digest,secret_digest,created_at,expires_at)
	    SELECT 'shr_'||lpad(n::text,22,'0'),$1,'url',$2,'bound-'||n,$3,$3,$4,$4::timestamptz+interval '7 days' FROM generate_series(1,256) n RETURNING id,team_id
	) INSERT INTO control.share_public_urls(share_id,team_id,public_url_id) SELECT id,team_id,$5 FROM inserted`, url.TeamID, request.ActingIdentityID, bytes.Repeat([]byte{9}, 32), now, url.ID)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	body, err := sharePolicyAt(t, d, scope, now)
	if err != nil || len(body.Policy.ShareVerifiers) != 256 {
		t.Fatal("maximum projection was truncated", err)
	}
	if _, err := visitorlease.Decode(body); err != nil {
		t.Fatal("maximum bounded projection rejected", err)
	}
	_, err = d.pool.Exec(t.Context(), `WITH inserted AS (
	    INSERT INTO control.shares(id,team_id,scope,created_by_identity_id,idempotency_key,request_digest,secret_digest,created_at,expires_at)
	    SELECT 'shr_'||lpad('257',22,'0'),team_id,scope,created_by_identity_id,'bound-257',request_digest,secret_digest,created_at,expires_at FROM control.shares LIMIT 1 RETURNING id,team_id
	) INSERT INTO control.share_public_urls(share_id,team_id,public_url_id) SELECT id,team_id,$1 FROM inserted`, url.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sharePolicyAt(t, d, scope, now); !errors.Is(err, ErrVisitorPolicy) {
		t.Fatal("overflow silently truncated current authority", err)
	}
}
