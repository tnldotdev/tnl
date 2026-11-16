package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationServiceHTTPSubjectAndAdmissionScope(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	if err := d.ConfigureIngressServicePorts(t.Context(), PrimaryIngressPoolID, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"a": {Target: "app:3000", Public: new(true)}, "b": {Target: "other:3000", Public: new(true)}}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	start := func(index int, key string) ServiceHTTPRun {
		t.Helper()
		a := replica.assignments.Services[index]
		access := deploymentAssignmentAccess(t, d, replica, a, now)
		prep, err := d.PrepareServiceRun(t.Context(), a.ServiceID, access.PublisherIdentity, key, now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "http", TrustRevision: a.TrustRevision}})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), a.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, run.RunID, run.RunNumber, run.Token, 0, now); err != nil {
			t.Fatal("prepare policy before certificate and publisher connections", err)
		}
		installPrivateTestCertificate(t, d, prep, run, now)
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
				t.Fatal(err)
			}
			if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
			t.Fatal(err)
		}
		return ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, RunID: run.RunID, Number: run.RunNumber, Token: credentials.ServiceRunToken(run.Token)}
	}
	a, b := start(0, "a"), start(1, "b")
	var claims int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_port_claims WHERE service_id=ANY($1)`, []string{a.Subject.ID, b.Subject.ID}).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("HTTP services consumed exclusive ingress port reservations", claims, err)
	}
	for _, service := range applied.Services {
		if service.Port != 443 {
			t.Fatal("HTTP service did not use shared HTTPS", service.Port)
		}
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "service-http", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), IngressPoolID: PrimaryIngressPoolID, HTTPS: true, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	routing, err := readIngressServiceRun(t.Context(), d, lease.IngressLeaseIdentity, a.Subject.ID, a.RunID, now)
	if err != nil || routing.RunNumber != a.Number || routing.Port != 443 || routing.Hostname == "" || len(routing.Relays) != 2 {
		t.Fatal("HTTP routing lost its exact ready run or shared endpoint", routing, err)
	}
	port := routing.Port
	source := netip.MustParseAddr("192.0.2.10")
	retry, err := readIngressServiceRun(t.Context(), d, lease.IngressLeaseIdentity, a.Subject.ID, a.RunID, now)
	if err != nil || !retry.ValidUntil.Equal(routing.ValidUntil) || retry.RunNumber != routing.RunNumber {
		t.Fatal("repeated routing changed its exact run or observation deadline", retry, err)
	}
	// run authentication remains at the policy boundary. exact visitor/source/
	// destination proofs and fixed setup/replay bounds are enforced at the
	// publisher and data-plane capacity owners, not by a control visitor row.
	for _, test := range []struct {
		name string
		auth ServiceHTTPRun
	}{
		{"other service", ServiceHTTPRun{Subject: b.Subject, RunID: a.RunID, Number: a.Number, Token: a.Token}},
		{"wrong run", ServiceHTTPRun{Subject: a.Subject, RunID: b.RunID, Number: a.Number, Token: a.Token}},
		{"wrong number", ServiceHTTPRun{Subject: a.Subject, RunID: a.RunID, Number: a.Number + 1, Token: a.Token}},
		{"wrong token", ServiceHTTPRun{Subject: a.Subject, RunID: a.RunID, Number: a.Number, Token: b.Token}},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := test.auth
			if _, err := d.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("HTTP policy widened its publisher run identity", err)
			}
		})
	}
	var visitors int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_service_visitors WHERE service_id=ANY($1)`, []string{a.Subject.ID, b.Subject.ID}).Scan(&visitors); err != nil || visitors != 0 {
		t.Fatal("HTTP preparation wrote visitor coordination rows", visitors, err)
	}
	grant, err := d.CreateServiceHTTPGrant(t.Context(), a.Subject.ID, r.ActorID, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	check := func(auth ServiceHTTPRun, source VisitorTokenSource, want bool) {
		t.Helper()
		issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, source, now)
		if !want {
			if err == nil {
				t.Fatal("widened service HTTP credential")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := d.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		local, err := visitorlease.New(auth.Subject, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		defer local.Close()
		if err := local.Apply(local.Begin(), update); err != nil {
			t.Fatal(err)
		}
		view, _, _ := local.Current()
		permission, err := visitortoken.VerifyBearer(issued.Token, view, now)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := local.Bind(permission, netip.MustParseAddr("192.0.2.10"), func() {})
		if err != nil {
			t.Fatal(err)
		}
		guard.Close()
	}
	check(a, GrantTokenSource{Credential: grant.RefreshCredential}, true)
	wrongAuth := a
	wrongAuth.Subject.Kind = "public_url"
	check(wrongAuth, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	check(b, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	check(a, GrantTokenSource{Credential: "shr_0123456789abcdefghijkl." + strings.Repeat("A", 43)}, false)
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), a.Subject, a.RunID, a.Number+1, a.Token.String(), 0, now); err == nil {
		t.Fatal("wrong run number fetched policy")
	}
	// browser credentials capture ready runs and stay separate from bearer
	// grants. a new pool member cannot redeem them.
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := d.BeginServiceBrowserLogin(t.Context(), a.Subject, "", "/settings?tab=1", strings.Repeat("n", 43), strings.Repeat("v", 43), binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ConsumeBrowserLogin(t.Context(), state, bytes.Repeat([]byte{8}, 32), now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatal("login binding ignored", err)
	}
	attempt, err := d.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	issued := browserTestControlSession(t, d, r.ActorID, now)
	handoff, err := d.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{IdentityID: r.ActorID, DisplayName: "operator", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(), AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt}, now)
	if err != nil {
		t.Fatal(err)
	}
	if port != 443 || !strings.HasPrefix(handoff.Origin, "https://") || strings.HasSuffix(handoff.Origin, ":443") {
		t.Fatal("handoff lost the canonical HTTPS origin", handoff.Origin)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), b, handoff.Token, now); err == nil {
		t.Fatal("other service redeemed handoff")
	}
	replica = enrollAppliedDeployment(t, d, r, enrollment, now)
	later := start(0, "later")
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), later, handoff.Token, now); err == nil {
		t.Fatal("later run redeemed handoff")
	}
	redemption, err := d.RedeemServiceBrowserHandoff(t.Context(), a, handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), a, handoff.Token, now); err == nil {
		t.Fatal("handoff replay")
	}
	check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, true)
	t.Run("refresh expired service browser access", func(t *testing.T) {
		// an idle browser retains its session after the short access token expires.
		now = now.Add(2 * time.Second)
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, issued.SessionID, now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, false)
		unavailable := errors.New("authority unavailable")
		if _, err := d.RefreshServiceBrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now, func(context.Context, string) (BrowserTokenRotation, error) {
			return BrowserTokenRotation{}, unavailable
		}); !errors.Is(err, unavailable) {
			t.Fatal("refresh lost authority failure", err)
		}
		check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, false)
		var calls atomic.Int32
		// renewal must survive retiring the key that encrypted its handoff.
		newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
		d.storageKey, err = storagekey.New(newKey, testStorageKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.CompleteStorageKeyRotation(t.Context()); err != nil {
			t.Fatal(err)
		}
		d.storageKey, err = storagekey.New(newKey, "")
		if err != nil {
			t.Fatal(err)
		}
		refresh := func(ctx context.Context, token string) (BrowserTokenRotation, error) {
			calls.Add(1)
			rotated, err := d.RefreshControlSession(ctx, credentials.RefreshToken(token), time.Hour, now)
			if err != nil {
				return BrowserTokenRotation{}, err
			}
			return BrowserTokenRotation{IdentityID: r.ActorID, AccessToken: rotated.AccessToken.String(), RefreshToken: rotated.RefreshToken.String(), AccessExpiresAt: rotated.AccessExpiresAt}, nil
		}
		if _, err := d.RefreshServiceBrowserSession(t.Context(), b.Subject.ID, redemption.CookieSecret, now, refresh); !errors.Is(err, ErrPreviewAccess) || calls.Load() != 0 {
			t.Fatal("another service refreshed the session", err)
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				session, err := d.RefreshServiceBrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now, refresh)
				if err != nil || !session.AccessExpiresAt.After(now) || !session.ExpiresAt.Equal(redemption.ExpiresAt) {
					t.Error("refresh failed or changed the browser deadline", err)
				}
			})
		}
		workers.Wait()
		if calls.Load() != 1 {
			t.Fatal("concurrent browser requests rotated more than once", calls.Load())
		}
		check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, true)
		// the stored rotated credential must work again, not only the first one.
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, issued.SessionID, now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.RefreshServiceBrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now, refresh); err != nil || calls.Load() != 2 {
			t.Fatal("rotated refresh credential was not retained", err)
		}
		check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, true)
		if _, err := d.RefreshServiceBrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, redemption.ExpiresAt, refresh); !errors.Is(err, ErrPreviewAccess) || calls.Load() != 2 {
			t.Fatal("refresh extended the original browser lifetime", err)
		}
	})
	if _, err = d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: "public_url", ID: "url_" + strings.Repeat("A", 22)}, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, now); err == nil {
		t.Fatal("service browser accepted a retired scope")
	}
	if _, err = d.ServiceBrowserSession(t.Context(), later, redemption.CookieSecret, false, now); err == nil {
		t.Fatal("browser session widened run scope")
	}
	t.Run("outside reviewer identity and share permission", func(t *testing.T) {
		ctx := WithControlPrincipal(t.Context(), ControlPrincipal{SessionID: issued.SessionID, IdentityID: r.ActorID})
		preview, err := d.CreatePreview(ctx, r.TeamID, r.ActorID, "service-review", now)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{a.Subject.ID, b.Subject.ID} {
			if _, err := d.AddPreviewService(ctx, AddPreviewServiceRequest{PreviewID: preview.ID, ServiceID: id, TeamID: r.TeamID, IdentityID: r.ActorID}, now); err != nil {
				t.Fatal(err)
			}
		}
		secret, raw, err := randomBrowserSecret()
		if err != nil {
			t.Fatal(err)
		}
		share, err := d.CreateShare(ctx, CreateShareRequest{PreviewID: preview.ID, TeamID: r.TeamID,
			ActingIdentityID: r.ActorID, ServiceIDs: []string{a.Subject.ID, b.Subject.ID}, EntryServiceID: b.Subject.ID,
			IdempotencyKey: "service-review", SecretFingerprint: sha256.Sum256(raw), ExpiresAt: now.Add(time.Hour)}, now)
		if err != nil || share.EntryServiceID != b.Subject.ID {
			t.Fatal("share lost its captured entry service", err)
		}
		decoded, _ := base64.RawURLEncoding.Strict().DecodeString(secret)
		shareSession, err := d.RedeemShare(t.Context(), a, share.ID, decoded, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		check(a, ShareSessionTokenSource{ShareID: share.ID, Secret: shareSession.CookieSecret, RunID: a.RunID}, true)
		outside, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", OIDCIdentity{
			Issuer: "https://identity.fixture.test", Subject: "outside-service-reviewer", DisplayName: "Sam",
			AssertionDigest: sha256.Sum256([]byte("outside-service-reviewer")), AssertionExpiry: now.Add(time.Hour),
		}, time.Hour, 24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		state, err := d.BeginServiceBrowserLogin(t.Context(), a.Subject, preview.ID, "/", strings.Repeat("n", 43), strings.Repeat("v", 43), binding, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := d.ConsumeBrowserLogin(t.Context(), state, binding, now)
		if err != nil {
			t.Fatal(err)
		}
		handoff, err := d.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{
			IdentityID: outside.Identity.Identity.ID, DisplayName: "not trusted",
			AccessToken: outside.AccessToken.String(), RefreshToken: outside.RefreshToken.String(),
			AccessExpiresAt: outside.AccessExpiresAt, ExpiresAt: outside.RefreshExpiresAt,
		}, now)
		if err != nil {
			t.Fatal("outside identity incorrectly required team visitor permission", err)
		}
		browser, err := d.RedeemServiceBrowserHandoff(t.Context(), a, handoff.Token, now)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := d.ServiceBrowserSession(t.Context(), a, browser.CookieSecret, false, now)
		if err != nil || !identity.Authenticated || identity.VisitAllowed || identity.TeamMember || identity.DisplayName != "Sam" {
			t.Fatal("browser identity was confused with share visitor permission", identity, err)
		}
		check(a, BrowserSessionTokenSource{Secret: browser.CookieSecret}, false)
		browserRaw, _ := base64.RawURLEncoding.Strict().DecodeString(browser.CookieSecret)
		shareRaw, _ := base64.RawURLEncoding.Strict().DecodeString(shareSession.CookieSecret)
		actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.10", ServiceRun: &a,
			BrowserCookieSecret: browserRaw, ShareID: share.ID, CookieSecret: shareRaw}
		thread, err := d.CreateFeedback(t.Context(), a, CreateFeedbackRequest{
			PreviewID: preview.ID, Service: "a", PagePath: "/", ReportText: "The label is unclear",
			Anchor:         json.RawMessage(`null`),
			Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
			SourceAtReport: feedbackTestSource(t), IdempotencyKey: "outside-report", Actor: actor,
		}, now)
		if err != nil || !thread.AuthorVerified || thread.AuthorIdentityID != outside.Identity.Identity.ID ||
			thread.AuthorDisplayName != "Sam" || thread.ServiceID != a.Subject.ID || thread.ServiceRunID != a.RunID || thread.RunNumber != a.Number {
			t.Fatal("service-backed report lost its verified author or exact run provenance", thread, err)
		}
		tx, err := d.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, _, nativeErr := privateVisitorAccess(t.Context(), tx, a.Subject.ID, outside.Identity.Identity.ID, now)
		_ = tx.Rollback(t.Context())
		if !errors.Is(nativeErr, ErrServiceAccess) {
			t.Fatal("HTTP share or browser identity granted connector permission", nativeErr)
		}
		if _, err := d.RevokeShare(ctx, share.ID, r.ActorID, now); err != nil {
			t.Fatal(err)
		}
		check(a, ShareSessionTokenSource{ShareID: share.ID, Secret: shareSession.CookieSecret, RunID: a.RunID}, false)
		if _, _, err := d.ReviewerFeedbackScope(t.Context(), a, preview.ID, actor, now); err == nil {
			t.Fatal("revoked share retained reviewer authority")
		}
		identity, err = d.ServiceBrowserSession(t.Context(), a, browser.CookieSecret, false, now)
		if err != nil || !identity.Authenticated || identity.VisitAllowed {
			t.Fatal("revoking a share destroyed independent browser identity", identity, err)
		}
	})
	// manual/company suspension invalidates both a signed-in visitor and the
	// current authority behind a service-scoped bearer grant, not the transport.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, r.TeamID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, false)
	check(a, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	current, err := readIngressServiceRun(t.Context(), d, lease.IngressLeaseIdentity, a.Subject.ID, a.RunID, now)
	if err != nil || current.RunNumber != a.Number || !current.ValidUntil.After(now) {
		t.Fatal("visitor suspension changed independent service routing", current, err)
	}
	// restore the actor's membership before changing publication configuration.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=NULL WHERE team_id=$1 AND identity_id=$2`, r.TeamID, r.ActorID); err != nil {
		t.Fatal(err)
	}
	t.Run("source policy apply retires previous publication", func(t *testing.T) {
		r.ExpectedRevision = applied.Revision
		service := r.Configuration.Services["a"]
		service.HTTP = &config.HTTPService{Access: &config.Access{IP: []string{"203.0.113.10"}}}
		r.Configuration.Services["a"] = service
		changed, err := d.ApplyProjectConfiguration(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		q := controlstatedb.New(d.pool)
		if _, err := d.serviceHTTPSourcePolicy(t.Context(), q, a.Subject.ID, source); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("current source policy retained the excluded source", err)
		}
		if _, err := d.serviceHTTPSourcePolicy(t.Context(), q, a.Subject.ID, netip.MustParseAddr("203.0.113.10")); err != nil {
			t.Fatal("current source policy rejected the configured source", err)
		}
		var retired bool
		if err := d.pool.QueryRow(t.Context(), `SELECT run.closed_at IS NOT NULL AND publisher_grant.revoked_at IS NOT NULL
		    FROM control.service_runs run JOIN control.publisher_grants publisher_grant ON publisher_grant.id=run.publisher_grant_id
		    WHERE run.id=$1`, a.RunID).Scan(&retired); err != nil || !retired {
			t.Fatal("changed HTTP configuration retained its previous run or publisher grant", retired, err)
		}
		if _, err := d.ReadPublisherVisitorPolicy(t.Context(), a.Subject, a.RunID, a.Number, a.Token.String(), 0, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("retired publication retained HTTP policy authority", err)
		}
		if _, err := readIngressServiceRun(t.Context(), d, lease.IngressLeaseIdentity, a.Subject.ID, a.RunID, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("retired publication remained in HTTP routing", err)
		}
		r.ExpectedRevision = changed.Revision
		service.HTTP = nil
		r.Configuration.Services["a"] = service
		if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if _, err := d.serviceHTTPSourcePolicy(t.Context(), q, a.Subject.ID, source); err != nil {
			t.Fatal("restored source policy rejected the original source", err)
		}
		if _, err := d.ReadPublisherVisitorPolicy(t.Context(), a.Subject, a.RunID, a.Number, a.Token.String(), 0, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("restoring source policy revived the retired publication policy", err)
		}
		if _, err := readIngressServiceRun(t.Context(), d, lease.IngressLeaseIdentity, a.Subject.ID, a.RunID, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("restoring source policy revived retired routing", err)
		}
	})
}

func mustOpaqueID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
