package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationRunAliasPreparationRetriesKeepSavedRandomHostname(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	var previous ServiceRunPreparation
	for range 2 {
		enrollment := publisherEnrollment(t, f.database, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID},
			PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: f.service.ID}, f.now)
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := f.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, f.now)
		if err != nil {
			t.Fatal(err)
		}
		request := ServiceRunRequest{Metadata: f.service.ServiceMetadata}
		first, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, publisher, "stable-random-alias", f.now, request)
		if err != nil {
			t.Fatal(err)
		}
		retry, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, publisher, "stable-random-alias", f.now, request)
		if err != nil || first.RunHostname == "" || retry.RunHostname != first.RunHostname ||
			retry.RunID != first.RunID || retry.RunNumber != first.RunNumber || retry.Token != first.Token {
			t.Fatal("preparation retry regenerated an alias or its run", err)
		}
		if first.RunID == previous.RunID || first.RunHostname == previous.RunHostname {
			t.Fatal("independent publisher runs reused an alias")
		}
		previous = first
	}
	var aliases, claims int
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_endpoints WHERE service_id=$1 AND service_run_id IS NOT NULL`,
		f.service.ID).Scan(&aliases); err != nil {
		t.Fatal(err)
	}
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_namespace_claims claim
	    JOIN control.service_endpoints endpoint ON endpoint.hostname=claim.namespace
	    WHERE endpoint.service_id=$1 AND endpoint.service_run_id IS NOT NULL`, f.service.ID).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if aliases != 2 || claims != 2 {
		t.Fatal("retries duplicated or omitted exact alias reservations", aliases, claims)
	}
}

func newRunAliasServiceFixture(t *testing.T) (serviceHTTPFixture, string, ProjectServiceConfiguration) {
	t.Helper()
	f := newServiceHTTPFixture(t)
	_, parent, ok := strings.Cut(f.service.Endpoint.Hostname, ".")
	if !ok {
		t.Fatal("fixture has no DNS parent")
	}
	declaration := ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3000",
		Public: new(true), RunAliasParent: parent}
	service, err := f.database.CreateServiceAt(t.Context(), f.project.TeamID, f.project.ActorID, "run-alias", "run-alias",
		ServicePlacement{DomainID: f.service.DomainID}, f.now, ServiceMetadata{Protocol: "http", PublisherPool: true}, &declaration)
	if err != nil {
		t.Fatal("create alias service", err)
	}
	f.service = service
	return f, parent, declaration
}

func TestIntegrationRunAliasPreparationAndManagedCertificate(t *testing.T) {
	f, parent, _ := newRunAliasServiceFixture(t)
	lease := registerServiceHTTPAdmissionIngress(t, t.Context(), f, "run-alias-reader")
	f.run = f.publish(t, f.service)
	var hostname string
	var identifiers []string
	var certificate time.Time
	if err := f.database.pool.QueryRow(t.Context(), `SELECT run_hostname,certificate_identifiers,certificate_expires_at
	    FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&hostname, &identifiers, &certificate); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^r-[a-z2-7]{26}\.`+regexp.QuoteMeta(parent)+`$`).MatchString(hostname) || !certificate.After(f.now) {
		t.Fatal("run did not retain its exact alias and managed certificate")
	}
	current, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 20})
	if err != nil || !current.PublicEndpointReady || !current.RunAliasReady || current.RunHostname != hostname {
		t.Fatal("unmanaged alias readiness was not distinct and current", err, current)
	}
	routing, err := readIngressServiceRun(t.Context(), f.database, lease.IngressLeaseIdentity, f.service.ID, f.run.RunID, f.now)
	if err != nil || routing.RunHostname == nil || *routing.RunHostname != hostname || routing.Hostname != f.service.Endpoint.Hostname {
		t.Fatal("routing omitted the ready alias or changed its canonical hostname", err)
	}
	var visitorWrites int
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_service_visitors`).Scan(&visitorWrites); err != nil || visitorWrites != 0 {
		t.Fatal("alias preparation or routing created visitor admission rows", err)
	}
}

func TestIntegrationRunAliasConfigurationPreservesRunAndTargetTrust(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	f.run = f.publish(t, f.service)
	original := f.service
	declaration.RunAliasParent = ""
	configured, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now.Add(time.Millisecond))
	if err != nil || configured.TrustRevision != original.TrustRevision || configured.EndpointRevision != original.EndpointRevision+1 {
		t.Fatal("alias configuration changed target trust or lost endpoint revision", err, configured.EndpointRevision, original.EndpointRevision)
	}
	current, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second),
		ServiceRunHealth{Healthy: true, StreamCapacity: 20})
	if err != nil || current.State != "ready" || current.RunAliasReady {
		t.Fatal("disabling aliases closed the run or retained alias readiness", err, current)
	}
	var retired bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT retired_at IS NOT NULL FROM control.service_endpoints WHERE service_run_id=$1`,
		f.run.RunID).Scan(&retired); err != nil || !retired {
		t.Fatal("disabling aliases retained their DNS authority", err)
	}
	declaration.RunAliasParent = "unowned.example"
	if _, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, configured.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("alias parent escaped its authorized domain", err)
	}
}

func TestIntegrationRunAliasVisitorPolicySelectsOnlyItsCurrentRun(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	f.run = f.publish(t, f.service)
	sibling := f.publish(t, f.service)
	auth := f.auth()
	for _, hostname := range []string{"", f.service.Endpoint.Hostname, f.run.RunHostname} {
		policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now, hostname)
		expected := hostname
		if expected == "" {
			expected = f.service.Endpoint.Hostname
		}
		if err != nil || policy.Policy.Hostname != expected || policy.Policy.PublicEndpoint == nil || policy.Policy.PublicEndpoint.Hostname != expected {
			t.Fatal("policy lost its selected hostname", hostname, err)
		}
	}
	for _, hostname := range []string{sibling.RunHostname, "foreign.example", strings.ToUpper(f.run.RunHostname)} {
		if _, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now, hostname); err == nil {
			t.Fatal("publisher obtained policy for another hostname", hostname)
		}
	}
	declaration.RunAliasParent = ""
	if _, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now, f.run.RunHostname); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("withdrawn alias still received visitor policy", err)
	}
	if _, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now); err != nil {
		t.Fatal("alias withdrawal interrupted canonical policy", err)
	}
}

func TestIntegrationRunAliasBrowserAndShareCredentialsStayHostBound(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	f.run = f.publish(t, f.service)
	sibling := f.publish(t, f.service)
	auth := f.auth()
	auth.Hostname = f.run.RunHostname
	preview := f.preview(t, "alias-browser", f.service)
	if _, err := f.database.SetPreviewTeamAccess(t.Context(), SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: f.project.TeamID, IdentityID: f.project.ActorID, Enabled: true,
	}, f.now); err != nil {
		t.Fatal(err)
	}
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := f.database.BeginServiceBrowserLogin(t.Context(), auth.Subject, preview.ID, "/settings",
		strings.Repeat("n", 32), strings.Repeat("v", 43), binding, nil, f.now, auth.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f.database.ConsumeBrowserLogin(t.Context(), state, binding, f.now)
	if err != nil || attempt.Hostname != auth.Hostname || !slices.Equal(attempt.ServiceRunIDs, []string{auth.RunID}) {
		t.Fatal("alias login captured another run or hostname", err)
	}
	session := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
	handoff, err := f.database.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{
		IdentityID: f.project.ActorID, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: session.RefreshExpiresAt,
	}, f.now)
	if err != nil || handoff.Origin != "https://"+auth.Hostname {
		t.Fatal("alias login redirected to the pooled endpoint", err)
	}
	wrong := auth
	wrong.RunID, wrong.Number = sibling.RunID, sibling.RunNumber
	if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), wrong, handoff.Token, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("sibling run redeemed the alias handoff", err)
	}
	if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("canonical host redeemed the alias handoff", err)
	}
	browser, err := f.database.RedeemServiceBrowserHandoff(t.Context(), auth, handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ServiceBrowserSession(t.Context(), f.auth(), browser.CookieSecret, false, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("alias browser cookie was accepted at the canonical host", err)
	}
	browserSource := BrowserSessionTokenSource{Secret: browser.CookieSecret}
	refresh := func(context.Context, string) (BrowserTokenRotation, error) {
		t.Fatal("a fresh browser session unexpectedly rotated its credentials")
		return BrowserTokenRotation{}, nil
	}
	if _, err := f.database.RefreshServiceBrowserSession(t.Context(), f.service.ID, browser.CookieSecret, f.now, refresh); !errors.Is(err, ErrPreviewAccess) {
		t.Fatal("alias browser cookie refreshed at the canonical host", err)
	}
	if _, err := f.database.RefreshServiceBrowserSession(t.Context(), f.service.ID, browser.CookieSecret, f.now, refresh, auth.Hostname); err != nil {
		t.Fatal("alias browser cookie could not refresh at its own host", err)
	}
	issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, browserSource, f.now, auth.Hostname)
	if err != nil || issued.Permission.Hostname != auth.Hostname {
		t.Fatal("browser permission did not retain its alias", err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, browserSource, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("alias browser cookie issued canonical permission", err)
	}
	policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now, auth.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := visitorlease.Decode(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyBearer(issued.Token, decoded.View, f.now); err != nil {
		t.Fatal("alias permission failed its host-bound policy", err)
	}
	canonical := decoded.View
	canonical.Hostname = f.service.Endpoint.Hostname
	if _, err := visitortoken.VerifyBearer(issued.Token, canonical, f.now); err == nil {
		t.Fatal("alias token verified for the canonical hostname")
	}
	secret := bytes.Repeat([]byte{8}, 32)
	share := f.share(t, preview.ID, "alias-share", secret, f.service)
	redemption, err := f.database.RedeemShare(t.Context(), auth, share.ID, secret, nil, f.now)
	if err != nil || redemption.NextURL != "https://"+auth.Hostname {
		t.Fatal("share opened on an alias returned to a sibling through the pool", err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret, RunID: auth.RunID}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, source, f.now, auth.Hostname); err != nil {
		t.Fatal("alias share cookie could not renew permission", err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, source, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("alias share cookie issued canonical permission", err)
	}
	canonicalShare, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalShare.CookieSecret == redemption.CookieSecret {
		t.Fatal("alias and canonical hosts reused a share cookie")
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject,
		DeviceTokenSource{DeviceID: "vdev_" + strings.Repeat("D", 22)}, f.now, auth.Hostname); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("connector source selected a public alias", err)
	}
	canonicalSource := ShareSessionTokenSource{ShareID: share.ID, Secret: canonicalShare.CookieSecret}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, canonicalSource, f.now, auth.Hostname); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("canonical share cookie issued alias permission", err)
	}
	declaration.RunAliasParent = ""
	if _, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, source, f.now, auth.Hostname); err == nil {
		t.Fatal("withdrawn alias still renewed share permission")
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, auth.Subject, canonicalSource, f.now); err != nil {
		t.Fatal("alias withdrawal interrupted canonical share permission", err)
	}
}

func TestIntegrationRunAliasChallengeCannotMoveToSiblingOrCanonicalHost(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	declaration.HTTP = &config.HTTPService{Protection: &httpprotection.Settings{WAF: httpprotection.Off}}
	var err error
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	sibling := f.publish(t, f.service)
	setProtectionSettings(t, f, httpprotection.Settings{WAF: httpprotection.Off, Challenge: httpprotection.Turnstile})
	auth := f.auth()
	browser, publisher, binding := challengeBindings()
	attempt, err := f.database.BeginHTTPChallenge(t.Context(), auth.Subject, browser[:], publisher[:], f.now, f.run.RunHostname)
	if err != nil || attempt.Hostname != f.run.RunHostname {
		t.Fatal("challenge did not capture its exact run hostname", err)
	}
	if err := f.database.ClaimHTTPChallenge(t.Context(), attempt.ID, browser[:], f.now); err != nil {
		t.Fatal(err)
	}
	handoff, err := f.database.CompleteHTTPChallenge(t.Context(), verifiedChallengeAttempt(t, attempt.ID, f.now), f.now)
	if err != nil || handoff.Origin != "https://"+f.run.RunHostname {
		t.Fatal("challenge redirected to the pooled endpoint", err)
	}
	if _, _, err := f.database.RedeemHTTPChallenge(t.Context(), auth.Subject, sibling.RunID, sibling.RunNumber,
		sibling.Token, handoff.Secret, binding, testVisitorIssuer, f.now, f.run.RunHostname); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("a sibling publisher redeemed another run's alias challenge", err)
	}
	if _, _, err := f.database.RedeemHTTPChallenge(t.Context(), auth.Subject, auth.RunID, auth.Number,
		auth.Token.String(), handoff.Secret, binding, testVisitorIssuer, f.now); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("canonical host redeemed alias clearance", err)
	}
	clearance, _, err := f.database.RedeemHTTPChallenge(t.Context(), auth.Subject, auth.RunID, auth.Number,
		auth.Token.String(), handoff.Secret, binding, testVisitorIssuer, f.now, f.run.RunHostname)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number,
		auth.Token.String(), 0, f.now, f.run.RunHostname)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := visitorlease.Decode(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyClearance(clearance, decoded.View, f.now); err != nil {
		t.Fatal("alias could not verify its clearance", err)
	}
	canonical := decoded.View
	canonical.Hostname = f.service.Endpoint.Hostname
	if _, err := visitortoken.VerifyClearance(clearance, canonical, f.now); err == nil {
		t.Fatal("alias clearance verified for the canonical hostname")
	}
	declaration.RunAliasParent = ""
	if _, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.BeginHTTPChallenge(t.Context(), auth.Subject, browser[:], publisher[:], f.now, f.run.RunHostname); err == nil {
		t.Fatal("a withdrawn alias started a new challenge")
	}
}
