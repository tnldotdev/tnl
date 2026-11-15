package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationVisitorShareSessionTokenUsesCapturedHostAndCurrentAuthority(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	f.run = f.publish(t, f.service)
	other := f.local(t, "api", nil)
	preview := f.preview(t, "share-session", f.service, other)
	secret := bytes.Repeat([]byte{4}, 32)
	share := f.share(t, preview.ID, "session-share", secret, f.service, other)
	redemption, err := d.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cookie)
	deadline := now.Add(40 * time.Second)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.share_cookies SET expires_at=$2 WHERE token_digest=$1`, digest[:], deadline); err != nil {
		t.Fatal(err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(cookie)}
	scope := f.auth().Subject
	issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
	if err != nil || issued.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) || !issued.Permission.ExpiresAt.Equal(deadline.Truncate(time.Second)) {
		t.Fatal("share session changed its scope, subject, or parent deadline", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: other.ID}, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("host-bound share session crossed to another captured public URL", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, ShareSessionTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share link secret became a share session", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, deadline); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("expired share session issued another visitor token", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, f.project.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share session survived its issuer losing current authority", err)
	}
}
