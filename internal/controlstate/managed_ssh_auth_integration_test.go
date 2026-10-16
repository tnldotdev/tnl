package controlstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"golang.org/x/crypto/ssh"
)

func managedSSHVisitorRun(t *testing.T) (*publishRunFixture, PublishRunAuthentication, string) {
	t.Helper()
	f, auth := finalVisitorRun(t, "postgres")
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if _, err = f.database.pool.Exec(t.Context(), `UPDATE control.public_urls SET service_protocol='ssh',ssh_host_key=$2 WHERE id=$1`, auth.PublicURLID, hostKey); err != nil {
		t.Fatal(err)
	}
	return f, auth, hostKey
}

func managedSSHSession(t *testing.T, f *publishRunFixture, identityID string) ControlSession {
	t.Helper()
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	session, err := f.database.createControlSession(t.Context(), controlstatedb.New(tx), identityID, false, oidcAuthenticationMethod, 1, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestIntegrationManagedSSHExplicitAccountGrants(t *testing.T) {
	f, auth, hostKey := managedSSHVisitorRun(t)
	d, owner := f.database, f.request.ActingIdentityID
	check := func(identity, user string, allowed bool) VisitorPermission {
		t.Helper()
		permission, err := d.SSHVisitorPermission(t.Context(), auth, identity, "192.0.2.9", user, f.now)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("SSH permission allowed=%t want=%t: %+v %v", permission.VisitAllowed, allowed, permission, err)
		}
		return permission
	}
	check(owner, "deploy", false)
	check("", "deploy", false)
	page, err := d.ListAvailablePublicURLs(t.Context(), owner, "", "", f.now)
	if err != nil || len(page.PublicURLs) != 0 {
		t.Fatalf("ownership-only SSH inventory: %+v %v", page, err)
	}
	session := managedSSHSession(t, f, owner)
	signed := false
	sign := func(urlID, identityID string, expires time.Time) ([]byte, error) {
		if urlID != auth.PublicURLID || identityID != owner {
			t.Fatal("certificate scope changed")
		}
		signed = true
		return []byte("certificate"), nil
	}
	if _, _, err = d.IssueVisitorCertificateScope(t.Context(), session.AccessToken, auth.PublicURLID, f.now, sign); !errors.Is(err, ErrPreviewAccess) || signed {
		t.Fatalf("ownership-only SSH certificate: signed=%t %v", signed, err)
	}
	url, err := d.GetPublicURLForAuthorization(t.Context(), auth.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReplaceVisitorAccess(t.Context(), url.ID, owner, VisitorAccessAnonymous, nil, url.MutationRevision, f.now); !errors.Is(err, ErrPublicURLInvalid) {
		t.Fatalf("SSH anonymous access replacement: %v", err)
	}
	if _, err = d.ReplaceVisitorAccess(t.Context(), url.ID, owner, VisitorAccessRestricted, nil, url.MutationRevision, f.now); err != nil {
		t.Fatalf("SSH restricted access replacement: %v", err)
	}
	for index, user := range []string{"", "root", "Root", "deploy\n", "a/b", "-deploy", "0deploy", strings.Repeat("a", 33)} {
		if authorization.SSHUserValid(user) {
			t.Fatalf("invalid account accepted: index %d", index)
		}
		if _, err = d.CreateIdentityVisitorGrant(t.Context(), auth.PublicURLID, owner, "invalid", owner, nil, f.now, user); !errors.Is(err, ErrShareInvalid) {
			t.Fatalf("invalid account grant: %v", err)
		}
	}
	if _, err = d.CreateTeamVisitorGrant(t.Context(), auth.PublicURLID, owner, "missing-account", nil, f.now); !errors.Is(err, ErrShareInvalid) {
		t.Fatalf("SSH grant without account: %v", err)
	}
	expires := f.now.Add(90 * time.Second)
	grant, err := d.CreateIdentityVisitorGrant(t.Context(), auth.PublicURLID, owner, "self", owner, &expires, f.now, "deploy")
	if err != nil || grant.SSHUser == nil || *grant.SSHUser != "deploy" {
		t.Fatalf("explicit self grant: %+v %v", grant, err)
	}
	for _, user := range []string{"deploy", ""} {
		permission := check(owner, user, true)
		if permission.SSHUser != "deploy" || permission.ExpiresAt == nil || !permission.ExpiresAt.Equal(expires) {
			t.Fatalf("account or grant expiry lost: %+v", permission)
		}
	}
	check(owner, "other", false)
	check(owner, "Deploy", false)
	check(owner, "root", false)
	if _, err = d.CreateIdentityVisitorGrant(t.Context(), auth.PublicURLID, owner, "self", owner, &expires, f.now, "other"); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("account missing from idempotency digest: %v", err)
	}
	if _, certExpiry, err := d.IssueVisitorCertificateScope(t.Context(), session.AccessToken, auth.PublicURLID, f.now, sign); err != nil || !signed || !certExpiry.Equal(expires.UTC().Truncate(time.Second)) {
		t.Fatalf("explicit SSH certificate: signed=%t expiry=%v %v", signed, certExpiry, err)
	}
	page, err = d.ListAvailablePublicURLs(t.Context(), owner, "", "", f.now)
	if err != nil || len(page.PublicURLs) != 1 || page.PublicURLs[0].SSHHostKey != hostKey || page.PublicURLs[0].VisitorAccess != "identity_grant" {
		t.Fatalf("explicit SSH inventory: %+v %v", page, err)
	}
	permission, err := identityPermission(t.Context(), controlstatedb.New(d.pool), auth.PublicURLID, owner, "", f.now)
	if err != nil || permission.VisitAllowed {
		t.Fatalf("generic identity permission authorized SSH: %+v %v", permission, err)
	}
	if err = d.RevokeVisitorGrant(t.Context(), auth.PublicURLID, owner, grant.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(owner, "deploy", false)
	if _, _, err = d.IssueVisitorCertificateScope(t.Context(), session.AccessToken, auth.PublicURLID, f.now, sign); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("revoked SSH certificate scope: %v", err)
	}
}

func TestIntegrationManagedSSHInvitationIPAndRun(t *testing.T) {
	f, auth, _ := managedSSHVisitorRun(t)
	d, owner := f.database, f.request.ActingIdentityID
	visitor := finalVisitorIdentity(t, d, f.now, "ssh-visitor@example.test")
	secret := bytes.Repeat([]byte{23}, 32)
	digest := sha256.Sum256(secret)
	expires := f.now.Add(time.Hour)
	invitation, err := d.CreateVisitorInvitation(t.Context(), auth.PublicURLID, owner, "ssh-invitation", "ssh-visitor@example.test", digest, expires, f.now, "app_user-1")
	if err != nil || invitation.SSHUser == nil || *invitation.SSHUser != "app_user-1" {
		t.Fatalf("SSH invitation: %+v %v", invitation, err)
	}
	if _, err = d.CreateVisitorInvitation(t.Context(), auth.PublicURLID, owner, "ssh-invitation", "ssh-visitor@example.test", digest, expires, f.now, "other"); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("invitation account missing from digest: %v", err)
	}
	grant, err := d.AcceptVisitorInvitation(t.Context(), visitor, invitation.ID+"."+base64.RawURLEncoding.EncodeToString(secret), f.now)
	if err != nil || grant.SSHUser == nil || *grant.SSHUser != "app_user-1" {
		t.Fatalf("SSH invitation account not copied: %+v %v", grant, err)
	}
	check := func(ip, user string, at time.Time, allowed bool) VisitorPermission {
		t.Helper()
		permission, err := d.SSHVisitorPermission(t.Context(), auth, visitor, ip, user, at)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("SSH permission allowed=%t want=%t: %+v %v", permission.VisitAllowed, allowed, permission, err)
		}
		return permission
	}
	permission := check("192.0.2.9", "app_user-1", f.now, true)
	if permission.ExpiresAt == nil || !permission.ExpiresAt.Equal(f.now.Add(2*time.Minute)) {
		t.Fatalf("SSH decision exceeds cache bound: %+v", permission)
	}
	check("192.0.2.9", "other", f.now, false)
	if _, err = d.CreateIdentityVisitorGrant(t.Context(), auth.PublicURLID, visitor, "visitor-management", visitor, nil, f.now, "other"); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("SSH visitor managed grants: %v", err)
	}
	ipExpiry := f.now.Add(20 * time.Second)
	ips, err := d.MutateVisitorIPs(t.Context(), auth.PublicURLID, owner, "set", "", []VisitorIPGrantInput{{Prefix: "192.0.2.0/24", ExpiresAt: &ipExpiry}, {Prefix: "198.51.100.0/24"}}, f.now)
	if err != nil || len(ips) != 2 {
		t.Fatalf("SSH IP policy: %+v %v", ips, err)
	}
	permission = check("192.0.2.9", "app_user-1", f.now, true)
	if permission.ExpiresAt == nil || !permission.ExpiresAt.Equal(ipExpiry) {
		t.Fatalf("SSH decision exceeds IP expiry: %+v", permission)
	}
	check("203.0.113.9", "app_user-1", f.now, false)
	check("192.0.2.9", "app_user-1", ipExpiry, false)
	for _, ip := range ips {
		if ip.Prefix == "192.0.2.0/24" {
			if _, err = d.MutateVisitorIPs(t.Context(), auth.PublicURLID, owner, "remove", ip.ID, nil, f.now); err != nil {
				t.Fatal(err)
			}
		}
	}
	check("192.0.2.9", "app_user-1", f.now, false)
	check("198.51.100.9", "app_user-1", f.now, true)
	runExpiry := f.now.Add(10 * time.Second)
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at=$2 WHERE id=$1`, auth.PublishRunID, runExpiry); err != nil {
		t.Fatal(err)
	}
	permission = check("198.51.100.9", "app_user-1", f.now, true)
	if permission.ExpiresAt == nil || !permission.ExpiresAt.Equal(runExpiry) {
		t.Fatalf("SSH decision exceeds run expiry: %+v", permission)
	}
	if err = d.RevokeVisitorInvitation(t.Context(), auth.PublicURLID, owner, invitation.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check("198.51.100.9", "app_user-1", f.now, false)
	wrong := auth
	wrong.PublishRunNumber++
	if _, err = d.SSHVisitorPermission(t.Context(), wrong, visitor, "198.51.100.9", "app_user-1", f.now); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("stale SSH run number: %v", err)
	}
	if err = d.ClosePublishRun(t.Context(), auth.PublishRunID, auth.PublishRunToken, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SSHVisitorPermission(t.Context(), auth, visitor, "198.51.100.9", "app_user-1", f.now); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("closed SSH run: %v", err)
	}
}

func TestIntegrationManagedSSHTeamGrantRequiresCurrentMembership(t *testing.T) {
	f, auth, _ := managedSSHVisitorRun(t)
	d, owner := f.database, f.request.ActingIdentityID
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, f.now, owner, f.request.TeamID, "ssh-member", TeamRoleMember)
	check := func(allowed bool) {
		t.Helper()
		permission, err := d.SSHVisitorPermission(t.Context(), auth, member.IdentityID, "192.0.2.9", "deploy", f.now)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("SSH membership allowed=%t want=%t: %+v %v", permission.VisitAllowed, allowed, permission, err)
		}
	}
	check(false)
	if _, err := d.CreateTeamVisitorGrant(t.Context(), auth.PublicURLID, owner, "ssh-team", nil, f.now, "deploy"); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := d.RemoveMembership(t.Context(), owner, f.request.TeamID, member.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestIntegrationManagedSSHAccountsForbiddenForOtherProtocols(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "mysql", "redis"} {
		t.Run(protocol, func(t *testing.T) {
			f, auth := finalVisitorRun(t, protocol)
			d, owner := f.database, f.request.ActingIdentityID
			if _, err := d.CreateTeamVisitorGrant(t.Context(), auth.PublicURLID, owner, "wrong-protocol", nil, f.now, "deploy"); !errors.Is(err, ErrShareInvalid) {
				t.Fatalf("non-SSH account grant: %v", err)
			}
			if _, err := d.CreateVisitorInvitation(t.Context(), auth.PublicURLID, owner, "wrong-protocol", "ssh@example.test", sha256.Sum256([]byte("secret")), f.now.Add(time.Hour), f.now, "deploy"); !errors.Is(err, ErrShareInvalid) {
				t.Fatalf("non-SSH account invitation: %v", err)
			}
		})
	}
}
