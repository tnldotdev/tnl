package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func finalVisitorRun(t *testing.T, protocol string) (*publishRunFixture, PublishRunAuthentication) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "final-visitor")
	creation := oidcRouteRequest(t, database, now)
	url := createTestPublicURL(t, database, creation, now)
	leases := make(map[string]RelayLease)
	for _, id := range []string{"final-visitor-a", "final-visitor-b"} {
		registration := relayLifecycleRegistration(id)
		registration.ConnectionCapacity = 10
		lease, err := database.RegisterRelay(t.Context(), registration, now, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	request := PublishRunRequest{PublicURLID: url.ID, TeamID: url.TeamID, ActingIdentityID: creation.ActingIdentityID, MembershipID: url.MembershipID,
		RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "final-visitor", RequestDigest: sha256.Sum256([]byte("final-visitor")), PolicyRevision: uint64(url.PolicyRevision),
		CertificateCacheKey: "final-visitor", CertificateScope: "public-url", CertificateIdentifiers: []string{url.CanonicalHostname}, CertificateChallenge: "dns-01", ExpectedMutationRevision: url.MutationRevision}
	setup, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{database: database, now: now, request: request, setup: setup, leases: leases}
	if protocol != "http" {
		t.Fatal("public URLs are HTTP-only")
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state='ready',ready_at=$2,publisher_expires_at=$3 WHERE id=$1`, f.setup.PublishRunID, f.now, f.now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &f, f.authentication()
}

func finalVisitorIdentity(t *testing.T, d *Database, now time.Time, email string) string {
	t.Helper()
	id, err := opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	insertAuthorityIdentity(t, d, id, email, email != "", now)
	return id
}

func TestIntegrationFinalVisitorGrantsInventoryInvitationAndRevocation(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d := f.database
	owner := f.request.ActingIdentityID
	visitor := finalVisitorIdentity(t, d, f.now, "visitor@example.test")
	check := func(person string, allowed bool, at time.Time) {
		t.Helper()
		permission, err := identityPermission(t.Context(), controlstatedb.New(d.pool), auth.PublicURLID, person, "", at)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("allowed=%t want=%t: %v", permission.VisitAllowed, allowed, err)
		}
	}
	check(owner, true, f.now)
	check(visitor, false, f.now)
	inventory, err := d.ListAvailablePublicURLs(t.Context(), visitor, "", "", f.now)
	if err != nil || len(inventory.PublicURLs) != 0 {
		t.Fatalf("outsider inventory: %+v %v", inventory, err)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	digest := sha256.Sum256(secret)
	invitation, err := d.CreateVisitorInvitation(t.Context(), auth.PublicURLID, owner, "named", "visitor@example.test", digest, f.now.Add(time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	token := invitation.ID + "." + base64.RawURLEncoding.EncodeToString(secret)
	wrong := finalVisitorIdentity(t, d, f.now, "another@example.test")
	if _, err = d.AcceptVisitorInvitation(t.Context(), wrong, token, f.now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("wrong verified email accepted: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := d.AcceptVisitorInvitation(t.Context(), visitor, token, f.now); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrShareNotFound) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent invitation successes=%d", successes)
	}
	check(visitor, true, f.now)
	check(visitor, false, f.now.Add(time.Hour))
	var memberships int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, f.request.TeamID, visitor).Scan(&memberships); err != nil || memberships != 0 {
		t.Fatalf("visitor gained membership: %d %v", memberships, err)
	}
	inventory, err = d.ListAvailablePublicURLs(t.Context(), visitor, "", "", f.now)
	if err != nil || len(inventory.PublicURLs) != 1 || inventory.PublicURLs[0].VisitorAccess != "identity_grant" {
		t.Fatalf("invited inventory: %+v %v", inventory, err)
	}
	encoded, _ := json.Marshal(inventory)
	for _, forbidden := range [][]byte{[]byte("target"), []byte("ip_policy"), []byte("token"), []byte("secret"), []byte("digest")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("visitor inventory exposed %s", forbidden)
		}
	}
	if err = d.RevokeVisitorInvitation(t.Context(), auth.PublicURLID, owner, invitation.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(visitor, false, f.now)
	if _, err = d.CreateTeamVisitorGrant(t.Context(), auth.PublicURLID, visitor, "outsider", nil, f.now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatalf("visitor managed grants: %v", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, f.now, owner, f.request.TeamID, "colleague", TeamRoleMember)
	grant, err := d.CreateTeamVisitorGrant(t.Context(), auth.PublicURLID, owner, "perpetual", nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	check(member.IdentityID, true, f.now.Add(2*time.Hour))
	if err = d.RemoveMembership(t.Context(), owner, f.request.TeamID, member.ID, f.now); err != nil {
		t.Fatal(err)
	}
	check(member.IdentityID, false, f.now)
	if err = d.RevokeVisitorGrant(t.Context(), auth.PublicURLID, owner, grant.ID, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationFinalVisitorLiveIPExpiryAndRunBoundary(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d := f.database
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, auth.PublicURLID); err != nil {
		t.Fatal(err)
	}
	expiry := f.now.Add(time.Second)
	for slot := range publishRunConnectionCount {
		claimTestConnection(t, *f, slot, f.now)
	}
	url, err := d.GetPublicURL(t.Context(), f.request.ActingIdentityID, auth.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReplaceVisitorAccess(t.Context(), url.ID, f.request.ActingIdentityID, VisitorAccessAnonymous, []string{"192.0.2.0/24"}, url.MutationRevision, f.now); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	grants, err := d.readVisitorIPs(t.Context(), q, url.ID, f.now)
	if err != nil || len(grants) != 1 {
		t.Fatalf("set IP grants: %+v %v", grants, err)
	}
	// expiration is a persisted-state boundary, not another public mutation API.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.visitor_ip_grants SET expires_at=$2 WHERE id=$1`, grants[0].ID, expiry); err != nil {
		t.Fatal(err)
	}
	check := func(at time.Time, want bool) {
		t.Helper()
		p, err := preparedPublicURLPermission(t.Context(), d, auth, preparedVisitorInput{SourceIP: "192.0.2.9"}, at)
		if err != nil || p.VisitAllowed != want {
			t.Fatalf("IP allowed=%t want=%t: %v", p.VisitAllowed, want, err)
		}
	}
	check(f.now, true)
	if permission, err := preparedPublicURLPermission(t.Context(), d, auth, preparedVisitorInput{SourceIP: "192.0.2.9"}, f.now); err != nil || permission.ExpiresAt == nil || !permission.ExpiresAt.Equal(expiry) {
		t.Fatalf("cached database decision outlived IP grant: %+v %v", permission, err)
	}
	check(expiry, false)
	var ciphertext []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT prefix_ciphertext FROM control.visitor_ip_grants WHERE id=$1`, grants[0].ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("192.0.2.")) {
		t.Fatal("IP grant was not encrypted", err)
	}
	if count, err := d.ExpireVisitorIPs(t.Context(), expiry); err != nil || count != 1 {
		t.Fatalf("expiry worker: %d %v", count, err)
	}
	var projectionJSON []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT projection FROM control.ingress_routing_table_events WHERE public_url_id=$1 AND event_kind='public_url_upsert' ORDER BY id DESC LIMIT 1`, auth.PublicURLID).Scan(&projectionJSON); err != nil {
		t.Fatal(err)
	}
	var projection IngressRoutingTableProjection
	if err = json.Unmarshal(projectionJSON, &projection); err != nil || projection.IPPolicy != IPPolicyAllowAll || len(projection.AllowedIPHashes) != 0 || len(projection.PublisherConnections) != 2 {
		t.Fatal("expired IP filter lost connected relay or unrestricted network policy", err)
	}
	if count, err := d.ExpireVisitorIPs(t.Context(), expiry); err != nil || count != 0 {
		t.Fatalf("expiry worker retry: %d %v", count, err)
	}
	url, err = d.GetPublicURL(t.Context(), f.request.ActingIdentityID, auth.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	url, err = d.ReplaceVisitorAccess(t.Context(), url.ID, f.request.ActingIdentityID, VisitorAccessAnonymous, []string{"198.51.100.9/32"}, url.MutationRevision, expiry)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.readVisitorIPs(t.Context(), q, url.ID, expiry)
	if err != nil || len(current) != 1 || current[0].Prefix != "198.51.100.9/32" {
		t.Fatal(current, err)
	}
	if _, err = d.ReplaceVisitorAccess(t.Context(), url.ID, f.request.ActingIdentityID, VisitorAccessAnonymous, nil, url.MutationRevision, expiry); err != nil {
		t.Fatal(err)
	}
	if current, err := d.readVisitorIPs(t.Context(), q, url.ID, expiry); err != nil || len(current) != 0 {
		t.Fatal("replaced IP set retained a grant", current, err)
	}
	wrong := auth
	wrong.PublishRunNumber++
	if _, err = preparedPublicURLPermission(t.Context(), d, wrong, preparedVisitorInput{SourceIP: "192.0.2.9"}, f.now); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatalf("wrong run number admitted: %v", err)
	}
	if err = d.ClosePublishRun(t.Context(), auth.PublishRunID, auth.PublishRunToken, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = preparedPublicURLPermission(t.Context(), d, auth, preparedVisitorInput{SourceIP: "192.0.2.9"}, f.now); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatalf("closed run admitted: %v", err)
	}
}

func finalBrowserSession(t *testing.T, f serviceHTTPFixture, previewID, identityID string) (string, ControlSession) {
	t.Helper()
	d := f.database
	handoff, issued := f.browser(t, previewID, identityID)
	cookie, err := d.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("handoff replay: %v", err)
	}
	return cookie.CookieSecret, issued
}

func TestIntegrationFinalVisitorBrowserIdentityFeedbackAuthorPolicyAndSessionRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	owner := f.project.ActorID
	preview := f.preview(t, "final-feedback", f.service)
	visitor := finalVisitorIdentity(t, d, f.now, "reviewer@example.test")
	cookie, issued := finalBrowserSession(t, f, preview.ID, visitor)
	p, err := d.ServiceBrowserSession(t.Context(), auth, cookie, false, f.now)
	if err != nil || p.IdentityID != visitor || p.VisitAllowed {
		t.Fatalf("identity alone admitted: %+v %v", p, err)
	}
	if err := d.CloseServiceRun(t.Context(), auth.Subject.ID, auth.RunID, auth.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	auth = f.auth()
	cookie, issued = finalBrowserSession(t, f, preview.ID, visitor)
	ip := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ServiceRun: &auth}
	report := CreateFeedbackRequest{PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "immutable report", AuthorDisplayName: "anonymous name", Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`), SourceAtReport: feedbackTestSource(t), IdempotencyKey: "anonymous", Actor: ip}
	anonymous, err := d.CreateFeedback(t.Context(), auth, report, f.now)
	if err != nil || anonymous.AuthorVerified {
		t.Fatal(anonymous, err)
	}
	if _, err = d.SetTeamFeedbackPolicy(t.Context(), owner, f.project.TeamID, "signed_in", f.now); err != nil {
		t.Fatal(err)
	}
	report.IdempotencyKey = "signin-required"
	if _, err = d.CreateFeedback(t.Context(), auth, report, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("anonymous policy bypass: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(cookie)
	signed := ip
	signed.BrowserCookieSecret = raw
	signed.DisplayName = "forged"
	report.Actor = signed
	report.IdempotencyKey = "signed"
	thread, err := d.CreateFeedback(t.Context(), auth, report, f.now)
	if err != nil || !thread.AuthorVerified || thread.AuthorIdentityID != visitor || thread.AuthorDisplayName == "forged" {
		t.Fatalf("verified author: %+v %v", thread, err)
	}
	for _, event := range []FeedbackEventType{FeedbackReply, FeedbackThreadResolved, FeedbackThreadReopened} {
		request := AppendFeedbackRequest{FeedbackID: thread.ID, Type: event, Text: "note", IdempotencyKey: string(event), Actor: ip}
		if _, err = d.AppendFeedback(t.Context(), request, f.now); !errors.Is(err, ErrVisitorSignIn) {
			t.Fatalf("anonymous %s bypass: %v", event, err)
		}
		request.Actor = signed
		stored, err := d.AppendFeedback(t.Context(), request, f.now)
		if err != nil || !stored.AuthorVerified || stored.AuthorIdentityID != visitor {
			t.Fatal(stored, err)
		}
	}
	original, err := d.GetFeedback(t.Context(), thread.ID)
	if err != nil || original.ReportText != thread.ReportText || original.AuthorIdentityID != thread.AuthorIdentityID {
		t.Fatal("report changed", err)
	}
	if _, err = d.SetTeamFeedbackPolicy(t.Context(), owner, f.project.TeamID, "team_members", f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "no permission", IdempotencyKey: "team-only", Actor: signed}, f.now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("nonmember author policy bypass: %v", err)
	}
	if err = d.RevokeControlSession(t.Context(), ControlPrincipal{IdentityID: visitor, SessionID: issued.SessionID}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ServiceBrowserSession(t.Context(), auth, cookie, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("revoked current control session admitted: %v", err)
	}
	if _, err = d.CreateFeedback(t.Context(), auth, report, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatalf("revoked browser wrote: %v", err)
	}
}

func TestIntegrationFinalVisitorDeviceEnrollmentRevocationAndIdentityBoundary(t *testing.T) {
	f, _ := finalVisitorRun(t, "http")
	d := f.database
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := f.request.ActingIdentityID
	device, err := d.EnrollVisitorDevice(t.Context(), identity, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.EnrollVisitorDevice(t.Context(), identity, key, f.now)
	if err != nil || retry.ID != device.ID {
		t.Fatal("device enrollment retry changed key identity", err)
	}
	other := finalVisitorIdentity(t, d, f.now, "device@example.test")
	if err = d.RevokeVisitorDevice(t.Context(), other, device.ID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("another identity revoked device: %v", err)
	}
	if err = d.RevokeVisitorDevice(t.Context(), identity, device.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.EnrollVisitorDevice(t.Context(), identity, key, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("revoked key was resurrected: %v", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, identity, f.now); err != nil {
		t.Fatal(err)
	}
	key, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.EnrollVisitorDevice(t.Context(), identity, key, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("disabled identity enrolled key: %v", err)
	}
}

func TestIntegrationFinalVisitorAdminBrowserHandoffHasIndependentSessionAndFollowsCLIRevocation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	parent := newOIDCSession(t, d, f.now)
	handoff, err := d.IssueControlBrowserHandoff(t.Context(), parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now)
	if err != nil || handoff.Origin == "" {
		t.Fatal(err)
	}
	cookie, err := d.RedeemServiceBrowserHandoff(t.Context(), auth, handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := browserDigest(cookie.CookieSecret)
	var sessionID, keyID string
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT control_session_id,storage_key_id,refresh_ciphertext FROM control.service_http_browser_sessions WHERE token_digest=$1`, digest).Scan(&sessionID, &keyID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	refresh, _, err := d.storageKey.Open(keyID, browserContext(digest), ciphertext)
	if err != nil || sessionID == parent.SessionID || string(refresh) == parent.RefreshToken.String() {
		t.Fatal("CLI control session or refresh token reused for browser", err)
	}
	if permission, err := d.ServiceBrowserSession(t.Context(), auth, cookie.CookieSecret, false, f.now); err != nil || !permission.VisitAllowed {
		t.Fatal(permission, err)
	}
	if err = d.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: parent.SessionID, IdentityID: parent.Identity.Identity.ID}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ServiceBrowserSession(t.Context(), auth, cookie.CookieSecret, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("browser survived parent revocation", err)
	}
	if _, err = d.IssueControlBrowserHandoff(t.Context(), parent.AccessToken, parent.RefreshToken, f.service.ID, time.Hour, 24*time.Hour, f.now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatal("revoked CLI created handoff", err)
	}
}

func TestIntegrationFinalVisitorHTTPDecisionUsesShareWithoutIPGrant(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	input := preparedVisitorInput{SourceIP: "192.0.2.9"}
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || p.VisitAllowed || p.IdentityID != "" {
		t.Fatal(p, err)
	}
	preview := f.preview(t, "visitor-shares", f.service)
	secret := bytes.Repeat([]byte{1}, 32)
	share := f.share(t, preview.ID, "anonymous", secret, f.service)
	redemption, err := d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	input.ShareID, input.ShareCookieSecret = share.ID, cookie
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || !p.VisitAllowed || p.IdentityID != "" || p.Reason != "anonymous_share" {
		t.Fatal(p, err)
	}
	if _, err = d.RevokeShare(t.Context(), share.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if p, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || p.VisitAllowed {
		t.Fatal("revoked share admitted", p, err)
	}
}

func TestIntegrationReplaceVisitorAccessChangesLiveRunWithoutIPBypass(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, owner := f.database, f.request.ActingIdentityID
	for slot := range publishRunConnectionCount {
		claimTestConnection(t, *f, slot, f.now)
	}
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT mutation_revision FROM control.public_urls WHERE id=$1`, auth.PublicURLID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	input := preparedVisitorInput{SourceIP: "192.0.2.9"}
	check := func(allowed bool) {
		t.Helper()
		permission, err := preparedPublicURLPermission(t.Context(), d, auth, input, f.now)
		if err != nil || permission.VisitAllowed != allowed {
			t.Fatalf("visitor allowed=%t, want %t: %v", permission.VisitAllowed, allowed, err)
		}
	}
	check(false)
	mode := VisitorAccessAnonymous
	publicURL, err := d.ReplaceVisitorAccess(t.Context(), auth.PublicURLID, owner, mode, []string{"192.0.2.0/24"}, uint64(revision), f.now)
	if err != nil || publicURL.AccessMode != mode || publicURL.MutationRevision != uint64(revision+1) {
		t.Fatalf("replace policy: %+v %v", publicURL, err)
	}
	check(true)
	input.SourceIP = "198.51.100.9"
	check(false)
	if _, err := d.ReplaceVisitorAccess(t.Context(), auth.PublicURLID, owner, VisitorAccessRestricted, nil, uint64(revision), f.now); !errors.Is(err, ErrPublicURLMutationStale) {
		t.Fatalf("stale policy replaced: %v", err)
	}
	publicURL, err = d.ReplaceVisitorAccess(t.Context(), auth.PublicURLID, owner, VisitorAccessRestricted, nil, uint64(revision+1), f.now)
	if err != nil || publicURL.AccessMode != VisitorAccessRestricted || publicURL.MutationRevision != uint64(revision+2) {
		t.Fatalf("remove filter: %+v %v", publicURL, err)
	}
	check(false)
	var projection IngressRoutingTableProjection
	var raw []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT projection FROM control.ingress_routing_table_events
		WHERE public_url_id=$1 AND event_kind='public_url_upsert' ORDER BY id DESC LIMIT 1`, auth.PublicURLID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &projection); err != nil || projection.AccessMode != VisitorAccessRestricted || projection.IPPolicy != IPPolicyAllowAll {
		t.Fatalf("latest ingress projection: %+v %v", projection, err)
	}
}

func TestIntegrationExactURLShareSecretAndCookieAreInterchangeable(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	auth := f.auth()
	d := f.database
	secret := bytes.Repeat([]byte{7}, 32)
	digest := sha256.Sum256(secret)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{
		TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: "automation", Label: "ci", SecretFingerprint: digest,
		ExpiresAt: f.now.Add(30 * time.Second), ServiceIDs: []string{f.service.ID}, EntryServiceID: f.service.ID,
	}, f.now)
	if err != nil || share.Scope != "service" || share.PreviewID != "" || !slices.Equal(share.ServiceIDs, []string{f.service.ID}) {
		t.Fatalf("exact URL share: %+v, %v", share, err)
	}
	input := preparedVisitorInput{SourceIP: "192.0.2.1", ShareID: share.ID, ShareSecret: secret}
	check := func(at time.Time, allowed bool) {
		t.Helper()
		decision, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, at)
		if err != nil || decision.VisitAllowed != allowed {
			t.Fatalf("share permission = %+v, want %t: %v", decision, allowed, err)
		}
	}
	check(f.now, true)
	if permission, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || permission.ExpiresAt == nil || permission.ExpiresAt.After(share.ExpiresAt) {
		t.Fatalf("HTTP decision outlived its share: %+v %v", permission, err)
	}
	redeemed, err := d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	input.ShareSecret, input.ShareCookieSecret = nil, cookie
	check(f.now, true)
	if permission, err := preparedServiceHTTPPermission(t.Context(), d, auth, input, f.now); err != nil || permission.ExpiresAt == nil || permission.ExpiresAt.After(share.ExpiresAt) {
		t.Fatalf("browser cookie decision outlived its share: %+v %v", permission, err)
	}
	if err := d.CloseServiceRun(t.Context(), auth.Subject.ID, auth.RunID, auth.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.0/24"}}})
	f.run = f.publish(t, f.service)
	auth = f.auth()
	check(f.now, false)
	redeemed, err = d.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	input.ShareCookieSecret, _ = base64.RawURLEncoding.Strict().DecodeString(redeemed.CookieSecret)
	input.SourceIP = "198.51.100.9"
	check(f.now, false)
	input.SourceIP = "192.0.2.1"
	check(f.now.Add(time.Hour), false)
	input.ShareID = "shr_other"
	check(f.now, false)
	input.ShareID, input.ShareSecret, input.ShareCookieSecret = share.ID, secret, nil
	if _, err := d.RevokeShare(t.Context(), share.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	check(f.now, false)
}
