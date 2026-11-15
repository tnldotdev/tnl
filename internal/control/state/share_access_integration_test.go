package state

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationShareAccessBindsPublisherAndRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now := f.database, f.now
	preview := f.preview(t, "share-test")
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	request := CreateShareRequest{PreviewID: preview.ID, TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: "share-test", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(24 * time.Hour),
		ServiceIDs: []string{f.service.ID}, EntryServiceID: f.service.ID}
	// sharing no longer has a publisher-side readiness phase. the current
	// preview membership authorizes creation; a real ready run redeems it.
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("unassigned preview authorized a share: %v", err)
	}
	f.preview(t, "share-test", f.service)
	share, err := database.CreateShare(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("missing publisher run redeemed share: %v", err)
	}
	f.run = f.publish(t, f.service)
	wrong := f.auth()
	wrong.Number++
	if _, err := database.RedeemShare(t.Context(), wrong, share.ID, secret, nil, now); err == nil {
		t.Fatal("wrong service run number redeemed share")
	}
	if _, err := database.RedeemShare(t.Context(), f.auth(), share.ID, []byte(strings.Repeat("x", 32)), nil, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("wrong secret redeemed: %v", err)
	}
	redemption, err := database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now)
	if err != nil || redemption.ShareID != share.ID || redemption.NextURL != "https://"+f.service.Endpoint.Hostname || redemption.CookieSecret == "" {
		t.Fatalf("redeemed link = %+v, %v", redemption, err)
	}
	cookie, err := base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	if err != nil || len(cookie) != 32 || strings.Contains(redemption.CookieSecret, ".") {
		t.Fatalf("issued cookie = %q, %v", redemption.CookieSecret, err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret, RunID: f.run.RunID}
	permission, err := database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, source, now)
	if err != nil || permission.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) {
		t.Fatal("redeemed session lost its exact share permission", err)
	}
	if _, err := database.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, source, now); err == nil {
		t.Fatal("service share authorized a public URL")
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, f.project.ActorID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, source, now.Add(2*time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked share session issued permission", err)
	}
	if _, err := database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now.Add(2*time.Second)); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("revoked share redeemed again: %v", err)
	}
}

func TestIntegrationShareHandoffIsShortLivedAndBoundToTheTargetPublicURL(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now := f.database, f.now
	f.run = f.publish(t, f.service)
	api := f
	api.service = f.local(t, "api", nil)
	api.run = f.publish(t, api.service)
	preview := f.preview(t, "handoff", f.service, api.service)
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share := f.share(t, preview.ID, "two-host-share", secret, f.service, api.service)
	initial, err := database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(initial.NextURL)
	if err != nil || parsed.Hostname() != api.service.Endpoint.Hostname {
		t.Fatalf("handoff hostname = %s, %v", initial.NextURL, err)
	}
	tokenText := strings.TrimPrefix(parsed.Path, "/__tnl/share/handoff/")
	if tokenText == parsed.Path {
		t.Fatalf("handoff path = %s", parsed.Path)
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(tokenText)
	if err != nil || len(token) != 32 {
		t.Fatalf("handoff token format = %v", err)
	}
	if _, err := database.RedeemShare(t.Context(), f.auth(), "", nil, token, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("handoff accepted on original host: %v", err)
	}
	digest := sha256.Sum256(token)
	var deadline time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT expires_at FROM control.share_handoffs WHERE token_digest=$1`, digest[:]).Scan(&deadline); err != nil ||
		!deadline.After(now) || deadline.After(now.Add(shareHandoffLifetime)) {
		t.Fatal("share handoff exceeded its short redemption deadline", deadline, err)
	}
	expiredAt := now.Add(time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.share_handoffs SET expires_at=$2 WHERE token_digest=$1`, digest[:], expiredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemShare(t.Context(), api.auth(), "", nil, token, expiredAt); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expired handoff accepted: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.share_handoffs SET expires_at=$2 WHERE token_digest=$1`, digest[:], deadline); err != nil {
		t.Fatal(err)
	}
	visited, err := database.RedeemShare(t.Context(), api.auth(), "", nil, token, now)
	if err != nil || visited.ShareID != share.ID || visited.NextURL != "https://"+f.service.Endpoint.Hostname || visited.CookieSecret == "" {
		t.Fatalf("redeemed handoff = %+v, %v", visited, err)
	}
	if _, err := database.RedeemShare(t.Context(), api.auth(), "", nil, token, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("handoff could be replayed: %v", err)
	}
	if err := database.ExpireVisitorPermissions(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	var cookies, handoffs int
	if err := database.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.share_cookies),(SELECT count(*) FROM control.share_handoffs)`).Scan(&cookies, &handoffs); err != nil || cookies != 2 || handoffs != 0 {
		t.Fatal("cleanup lost live share cookies or retained a consumed handoff", cookies, handoffs, err)
	}
	if err := database.ExpireVisitorPermissions(t.Context(), share.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.share_cookies`).Scan(&cookies); err != nil || cookies != 0 {
		t.Fatal("share cookie cleanup depended on a publisher snapshot read", cookies, err)
	}
}
