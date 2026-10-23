package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationVisitorShareSessionTokenUsesCapturedHostAndCurrentAuthority(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_share_session")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	otherRequest := request
	otherRequest.IdempotencyKey, otherRequest.CanonicalHostname = "other-session", "other."+request.CanonicalHostname
	otherRequest.RequestDigest = sha256.Sum256([]byte("other-session"))
	other := createTestPublicURL(t, d, otherRequest, now)
	preview, err := d.CreatePreview(t.Context(), url.TeamID, request.ActingIdentityID, "share-session", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, captured := range []PublicURL{url, other} {
		if _, err := d.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{PreviewID: preview.ID, PublicURLID: captured.ID, TeamID: url.TeamID,
			IdentityID: request.ActingIdentityID, PolicyRevision: uint64(captured.PolicyRevision), ExpectedMutationRevision: captured.MutationRevision}, now); err != nil {
			t.Fatal(err)
		}
	}
	secret := bytes.Repeat([]byte{4}, 32)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{PreviewID: preview.ID, TeamID: url.TeamID, ActingIdentityID: request.ActingIdentityID, IdempotencyKey: "session-share",
		SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
		PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}, {PublicURLID: other.ID, ExpectedMutationRevision: other.MutationRevision}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie := bytes.Repeat([]byte{9}, 32)
	digest := sha256.Sum256(cookie)
	q := controlstatedb.New(d.pool)
	if _, err := q.InsertShareCookie(t.Context(), controlstatedb.InsertShareCookieParams{TokenDigest: digest[:], ShareID: share.ID, PublicURLID: url.ID, CreatedAt: timestamptz(now)}); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(40 * time.Second)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.share_cookies SET expires_at=$2 WHERE token_digest=$1`, digest[:], deadline); err != nil {
		t.Fatal(err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(cookie)}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
	if err != nil || issued.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) || !issued.Permission.ExpiresAt.Equal(deadline.Truncate(time.Second)) {
		t.Fatal("share session changed its scope, subject, or parent deadline", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: other.ID}, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("host-bound share session crossed to another captured public URL", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ShareSessionTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share link secret became a share session", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, deadline); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("expired share session issued another visitor token", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, request.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share session survived its issuer losing current authority", err)
	}
}
