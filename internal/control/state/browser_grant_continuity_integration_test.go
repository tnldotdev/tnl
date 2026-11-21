package state

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationBrowserGrantContinuityAcrossMigration(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	d, ctx := f.database, t.Context()
	reviewer := finalVisitorIdentity(t, d, f.now, "disconnected@example.test")
	parent := browserTestControlSession(t, d, reviewer, f.now)
	grant, err := d.CreateServiceGrant(ctx, f.service.ID, f.project.ActorID, "before", "identity", reviewer, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := d.IssueControlBrowserHandoff(ctx, parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	auth := f.auth()
	cookie, err := d.RedeemServiceBrowserHandoff(ctx, auth, handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	direct, migrations := watchMigrationFixture(t, d)
	if _, err := migrations.DownTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, direct); err != nil {
		t.Fatal(err)
	}
	source := BrowserSessionTokenSource{Secret: cookie.CookieSecret}
	var clock atomic.Pointer[time.Time]
	clock.Store(&f.now)
	lease, err := visitorlease.New(auth.Subject, func() time.Time { return *clock.Load() })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	observe := func(at time.Time) {
		t.Helper()
		clock.Store(&at)
		begin := lease.Begin()
		policy, err := d.ReadPublisherVisitorPolicy(ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), begin.AfterRevision, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Apply(begin, update); err != nil {
			t.Fatal(err)
		}
	}
	permission := func(at time.Time, wantGrant string) visitortoken.VerifiedPermission {
		t.Helper()
		token, err := d.IssueVisitorToken(ctx, testVisitorIssuer, auth.Subject, source, at)
		if err != nil {
			t.Fatal(err)
		}
		view, _, _ := lease.Current()
		verified, err := visitortoken.VerifyBearer(token.Token, view, at)
		if err != nil {
			t.Fatal(err)
		}
		if got := verified.Facts().BrowserGrantID; got != wantGrant {
			t.Fatalf("signed browser grant = %q, want %q", got, wantGrant)
		}
		return verified
	}
	observe(f.now)
	before := permission(f.now, grant.ID)
	peer := netip.MustParseAddr("192.0.2.1")
	guard, err := lease.Bind(before, peer, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Renew(permission(f.now.Add(time.Second), grant.ID)); err != nil {
		t.Fatal("the same grant did not renew", err)
	}

	// let both transactions commit before the publisher observes policy again.
	revokedAt, regrantedAt := f.now.Add(2*time.Second), f.now.Add(3*time.Second)
	if err := d.RevokeServiceGrant(ctx, f.service.ID, f.project.ActorID, grant.ID, revokedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, auth.Subject, source, revokedAt); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("control did not deny access between grants", err)
	}
	replacement, err := d.CreateServiceGrant(ctx, f.service.ID, f.project.ActorID, "after", "identity", reviewer, nil, regrantedAt)
	if err != nil {
		t.Fatal(err)
	}
	observe(regrantedAt)
	after := permission(regrantedAt, replacement.ID)
	if !after.SameIdentity(before) || after.SameAdmission(before) {
		t.Fatal("replacement must preserve identity but not admission")
	}
	if err := guard.Renew(after); err == nil {
		t.Fatal("replacement grant renewed the old admission")
	}
	fresh, err := lease.Bind(after, peer, func() {})
	if err != nil {
		t.Fatal("replacement grant did not admit a new request", err)
	}
	fresh.Close()
}
