package public

import (
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// exercise the same strict client used by service sharing against real authority
// state; no publisher or visitor transport is needed to prove grant isolation.
func TestIntegrationServiceAccessClient(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "service_access_client")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ownerSession, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	owner, err := clientcontrol.New(server.URL, server.Client(), ownerSession.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	person := func(subject, email string) (*clientcontrol.Client, string) {
		t.Helper()
		session, err := d.CreateOIDCControlSession(ctx, "example.test", controlstate.OIDCIdentity{
			Issuer: "https://identity.fixture.test", Subject: subject, DisplayName: subject,
			NormalizedEmail: email, EmailVerified: email != "", AssertionDigest: sha256.Sum256([]byte(subject)), AssertionExpiry: now.Add(time.Hour),
		}, time.Hour, 24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		client, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return client, session.Identity.Identity.ID
	}
	visitor, visitorID := person("visitor", "visitor@example.test")
	wrongEmail, _ := person("other", "other@example.test")
	unverified, _ := person("unverified", "")
	team := ownerSession.Identity.Memberships[0].TeamID
	a, err := owner.CreateService(ctx, team, "orders", "orders")
	if err != nil {
		t.Fatal(err)
	}
	b, err := owner.CreateService(ctx, team, "another", "another")
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(time.Hour)
	body := controlv1.CreateServiceInvitationRequest{Email: "visitor@example.test", ExpiresAt: deadline}
	denied := func(err error) {
		t.Helper()
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResourceNotFound || !errors.Is(err, clientcontrol.ErrNotFound) {
			t.Fatalf("expected current manager/email/scope rejection, got %v", err)
		}
	}
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(31 * 24 * time.Hour)} {
		invalid := body
		invalid.ExpiresAt = at
		_, err := owner.InviteServiceVisitor(ctx, a.Id, "invalid-deadline", invalid)
		denied(err)
	}
	invite, err := owner.InviteServiceVisitor(ctx, a.Id, "one-invitation", body)
	if err != nil || invite.Secret == nil || invite.ServiceId != a.Id || !invite.ExpiresAt.Equal(deadline) {
		t.Fatalf("create exact invitation: %+v %v", invite, err)
	}
	if retry, err := owner.InviteServiceVisitor(ctx, a.Id, "one-invitation", body); err != nil || retry.Id != invite.Id || retry.Secret != nil {
		t.Fatal("invitation creation retry lost its ID or reissued a secret", err)
	}
	for _, client := range []*clientcontrol.Client{wrongEmail, unverified} {
		_, err := client.AcceptServiceInvitation(ctx, *invite.Secret)
		denied(err)
	}
	grant, err := visitor.AcceptServiceInvitation(ctx, *invite.Secret)
	if err != nil || grant.ServiceId != a.Id || grant.Kind != "identity" || grant.IdentityId == nil || *grant.IdentityId != visitorID || grant.InvitationId == nil || *grant.InvitationId != invite.Id || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(deadline) {
		t.Fatalf("accepted exact invitation grant: %+v %v", grant, err)
	}
	_, err = visitor.AcceptServiceInvitation(ctx, *invite.Secret)
	denied(err)
	if retry, err := owner.InviteServiceVisitor(ctx, a.Id, "one-invitation", body); err != nil || retry.Id != invite.Id || retry.Secret != nil || retry.AcceptedAt == nil {
		t.Fatal("accepted retry lost its current state or reissued a secret", err)
	}
	invitations, err := owner.ListServiceInvitations(ctx, a.Id)
	if err != nil || len(invitations) != 1 || invitations[0].Secret != nil || invitations[0].AcceptedAt == nil {
		t.Fatalf("listed accepted invitation: %+v %v", invitations, err)
	}
	grants, err := owner.ListServiceGrants(ctx, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range grants {
		if g.ServiceId != a.Id || g.Kind != "identity" {
			t.Fatal("invitation widened to a team or another resource", g)
		}
		found = found || g.Id == grant.Id
	}
	if !found {
		t.Fatal("accepted invitation grant missing from manager list")
	}
	available, err := visitor.ListAvailableServices(ctx)
	if err != nil || len(available) != 1 || available[0].Id != a.Id {
		t.Fatalf("invitation widened visitor inventory: %+v %v", available, err)
	}
	expired, _, err := d.ListAvailableServices(ctx, visitorID, "", deadline.Add(time.Second))
	if err != nil || len(expired) != 0 {
		t.Fatalf("invitation grant outlived its original deadline: %+v %v", expired, err)
	}
	identity, err := d.IdentityContext(ctx, visitorID)
	if err != nil || len(identity.Memberships) != 1 || identity.Memberships[0].TeamID == team {
		t.Fatal("service invitation created team membership", err)
	}
	_, err = visitor.ListServiceGrants(ctx, a.Id)
	denied(err)
	_, err = visitor.ListServiceInvitations(ctx, a.Id)
	denied(err)
	_, err = visitor.InviteServiceVisitor(ctx, a.Id, "visitor-cannot-manage", body)
	denied(err)
	denied(visitor.RevokeServiceInvitation(ctx, a.Id, invite.Id))
	denied(owner.RevokeServiceInvitation(ctx, b.Id, invite.Id))
	denied(owner.RevokeServiceGrant(ctx, b.Id, grant.Id))
	if err := owner.RevokeServiceInvitation(ctx, a.Id, invite.Id); err != nil {
		t.Fatal(err)
	}
	if retry, err := owner.InviteServiceVisitor(ctx, a.Id, "one-invitation", body); err != nil || retry.Id != invite.Id || retry.Secret != nil || retry.RevokedAt == nil {
		t.Fatal("retry revived a revoked invitation", err)
	}
	invitations, err = owner.ListServiceInvitations(ctx, a.Id)
	if err != nil || len(invitations) != 1 || invitations[0].RevokedAt == nil {
		t.Fatalf("invitation revocation was not visible to the manager: %+v %v", invitations, err)
	}
	grants, err = owner.ListServiceGrants(ctx, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.Id == grant.Id && g.RevokedAt == nil {
			t.Fatal("revoking the accepted invitation retained its derived grant")
		}
	}
	available, err = visitor.ListAvailableServices(ctx)
	if err != nil || len(available) != 0 {
		t.Fatalf("revoked invitation retained visitor access: %+v %v", available, err)
	}
	invite, err = owner.InviteServiceVisitor(ctx, a.Id, "grant-revocation", body)
	if err != nil || invite.Secret == nil {
		t.Fatal("second invitation", err)
	}
	grant, err = visitor.AcceptServiceInvitation(ctx, *invite.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.RevokeServiceGrant(ctx, a.Id, grant.Id); err != nil {
		t.Fatal(err)
	}
	available, err = visitor.ListAvailableServices(ctx)
	if err != nil || len(available) != 0 {
		t.Fatalf("revoked identity grant retained visitor access: %+v %v", available, err)
	}
	if err := d.RevokeControlSession(ctx, controlstate.ControlPrincipal{IdentityID: ownerSession.Identity.Identity.ID, SessionID: ownerSession.SessionID}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err = owner.ListServiceInvitations(ctx, a.Id)
	if !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked manager session remained authorized", err)
	}
	_, err = owner.InviteServiceVisitor(ctx, a.Id, "one-invitation", body)
	if !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("retry bypassed revoked manager session", err)
	}
}
