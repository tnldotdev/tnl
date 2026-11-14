package state

import (
	"bytes"
	"context"
	"encoding/base64"
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
			if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
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
	admit := func(auth ServiceHTTPRun) (string, int) {
		t.Helper()
		port := 0
		hostname := ""
		for _, s := range applied.Services {
			if s.ServiceID == auth.Subject.ID {
				port = s.Port
				hostname = s.Hostname
			}
		}
		visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		if _, err := d.AdmitPublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, hostname, port, netip.MustParseAddr("192.0.2.10"), now); err != nil {
			t.Fatal(err)
		}
		return visitor, port
	}
	visitor, port := admit(a)
	source := netip.MustParseAddr("192.0.2.10")
	pending, err := d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
	if err != nil || pending.State != PublicServiceVisitorPending {
		t.Fatal("valid HTTP transport claimed request permission", pending, err)
	}
	retry, err := d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now.Add(time.Second))
	if err != nil || retry.State != PublicServiceVisitorPending || !retry.ValidUntil.Equal(pending.ValidUntil) {
		t.Fatal("pending status extended its original deadline", retry, err)
	}
	if err := d.PromotePublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, visitor, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ingress promoted HTTP before request permission", err)
	}
	for _, test := range []struct {
		name string
		auth ServiceHTTPRun
		ip   netip.Addr
		port int
		id   string
	}{
		{"other service", b, source, 443, visitor},
		{"wrong run", ServiceHTTPRun{Subject: a.Subject, RunID: b.RunID, Number: a.Number, Token: a.Token}, source, 443, visitor},
		{"wrong number", ServiceHTTPRun{Subject: a.Subject, RunID: a.RunID, Number: a.Number + 1, Token: a.Token}, source, 443, visitor},
		{"wrong token", ServiceHTTPRun{Subject: a.Subject, RunID: a.RunID, Number: a.Number, Token: b.Token}, source, 443, visitor},
		{"wrong source", a, netip.MustParseAddr("192.0.2.11"), 443, visitor},
		{"wrong port", a, source, 25443, visitor},
		{"unknown visitor", a, source, 443, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := d.AuthorizeServiceHTTPVisitor(t.Context(), test.auth, test.id, test.ip, test.port, now); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("HTTP authorization widened its forwarding identity", err)
			}
		})
	}
	if expired, err := d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, pending.ValidUntil); err != nil || expired.State != PublicServiceVisitorDenied {
		t.Fatal("pending HTTP transport survived its fixed deadline", expired, err)
	}
	if _, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, pending.ValidUntil); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("publisher revived an expired pending visitor", err)
	}
	for _, hostname := range []string{"", "unknown.example.test", "UPPER.example.test"} {
		if _, err := d.AdmitPublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, PrimaryIngressPoolID, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), hostname, 443, netip.MustParseAddr("192.0.2.10"), now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("shared HTTPS selected a missing or invalid hostname", err)
		}
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
	decision, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, now)
	if err != nil || !decision.Allowed || decision.Admitted {
		t.Fatal("publisher permission bypassed ingress acknowledgment", decision, err)
	}
	repeated, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, now)
	if err != nil || repeated != decision {
		t.Fatal("repeated HTTP authorization was not idempotent", repeated, err)
	}
	status, err := d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != PublicServiceVisitorAuthenticated {
		t.Fatal("transport bypassed promotion", status, err)
	}
	if err = d.PromotePublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, visitor, now); err != nil {
		t.Fatal(err)
	}
	status, err = d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != PublicServiceVisitorAllowed {
		t.Fatal(status, err)
	}
	decision, err = d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, now)
	if err != nil || !decision.Allowed || !decision.Admitted {
		t.Fatal("publisher did not observe ingress acknowledgment", decision, err)
	}
	closed, _ := admit(a)
	if err := d.ClosePublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, closed, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, closed, source, 443, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("publisher revived a closed visitor", err)
	}
	wrongAuth := a
	wrongAuth.Subject.Kind = visitorscope.PublicURL
	check(wrongAuth, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	check(b, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	check(a, GrantTokenSource{Credential: "shr_0123456789abcdefghijkl." + strings.Repeat("A", 43)}, false)
	if _, err := d.ReadPublisherVisitorPolicy(t.Context(), a.Subject, a.RunID, a.Number+1, a.Token.String(), 0, now); err == nil {
		t.Fatal("wrong run number fetched policy")
	}
	// browser credentials capture ready runs and stay separate from legacy URL
	// sessions and managed bearer grants. a new pool member cannot redeem them.
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := d.BeginServiceBrowserLogin(t.Context(), a.Subject, "/settings?tab=1", strings.Repeat("n", 43), strings.Repeat("v", 43), binding, nil, now)
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
	if _, err = d.BrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now); err == nil {
		t.Fatal("managed browser widened legacy URL scope")
	}
	if _, err = d.ServiceBrowserSession(t.Context(), later, redemption.CookieSecret, false, now); err == nil {
		t.Fatal("browser session widened run scope")
	}
	// manual/company suspension invalidates both a signed-in visitor and the
	// current authority behind a service-scoped bearer grant, not the transport.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, r.TeamID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	check(a, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, false)
	check(a, GrantTokenSource{Credential: grant.RefreshCredential}, false)
	status, err = d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != PublicServiceVisitorAllowed {
		t.Fatal("HTTP authority changed its independent transport lease", status, err)
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
		if _, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("retired publication retained HTTP visitor authorization", err)
		}
		status, err := d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
		if err != nil || status.State != PublicServiceVisitorDenied {
			t.Fatal("retired publication retained its promoted HTTP transport", status, err)
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
		if _, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, visitor, source, 443, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("restoring source policy revived the retired publication", err)
		}
		status, err = d.PublicServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, visitor, now)
		if !errors.Is(err, ErrServiceAccess) || status.State != PublicServiceVisitorDenied {
			t.Fatal("restoring source policy revived the retired visitor", status, err)
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
