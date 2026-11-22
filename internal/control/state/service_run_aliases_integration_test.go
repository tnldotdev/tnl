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

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationRunAliasPreparationRetriesKeepSavedRandomHostname(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	var previous ServiceRunPreparation
	aliasRevision := func(run string) int64 {
		t.Helper()
		var revision int64
		if err := f.database.pool.QueryRow(t.Context(), `SELECT revision FROM control.run_alias_watch_versions WHERE service_run_id=$1`, run).Scan(&revision); err != nil {
			t.Fatal("missing alias binding revision", err)
		}
		return revision
	}
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
		if err := f.database.CloseServiceRun(t.Context(), f.service.ID, first.RunID, first.Token, f.now); err != nil {
			t.Fatal("retire the first publisher run", err)
		}
		retired := aliasRevision(first.RunID)
		replacement, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, publisher, "replacement-random-alias", f.now, request)
		if err != nil || replacement.RunHostname != first.RunHostname || replacement.RunID == first.RunID || replacement.RunNumber <= first.RunNumber {
			t.Fatal("publisher restart changed its saved address or reused its old run", err)
		}
		if aliasRevision(first.RunID) <= retired || aliasRevision(replacement.RunID) == 0 {
			t.Fatal("alias handoff did not invalidate both run bindings")
		}
		var owner string
		if err := f.database.pool.QueryRow(t.Context(), `SELECT service_run_id FROM control.service_endpoints WHERE hostname=$1 AND retired_at IS NULL`,
			first.RunHostname).Scan(&owner); err != nil || owner != replacement.RunID {
			t.Fatal("saved address did not advance to the current run", err)
		}
		if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, publisher, "stable-random-alias", f.now, request); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("a retry of a closed run regained authority", err)
		}
		if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, first.RunID, first.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err == nil {
			t.Fatal("a heartbeat from the old run regained authority")
		}
		if err := f.database.CloseServiceRun(t.Context(), f.service.ID, first.RunID, first.Token, f.now); err != nil {
			t.Fatal("retrying the old close failed", err)
		}
		if err := f.database.pool.QueryRow(t.Context(), `SELECT service_run_id FROM control.service_endpoints WHERE hostname=$1 AND retired_at IS NULL`,
			first.RunHostname).Scan(&owner); err != nil || owner != replacement.RunID {
			t.Fatal("stale run updates changed the replacement's address", err)
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

func TestIntegrationRunAliasParentAndExposurePreservePublisherBinding(t *testing.T) {
	f, parent, declaration := newRunAliasServiceFixture(t)
	ctx := t.Context()
	enrollment := publisherEnrollment(t, f.database, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID},
		PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: f.service.ID}, f.now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.database.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	start := func(key string) ServiceRunPreparation {
		t.Helper()
		f.now = f.now.Add(time.Second)
		run, err := f.database.PrepareServiceRun(ctx, f.service.ID, publisher, key, f.now,
			ServiceRunRequest{Metadata: f.service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	closeRun := func(run ServiceRunPreparation) {
		t.Helper()
		if err := f.database.CloseServiceRun(ctx, f.service.ID, run.RunID, run.Token, f.now); err != nil {
			t.Fatal(err)
		}
	}
	configure := func(parent string, public bool) {
		t.Helper()
		f.now = f.now.Add(time.Second)
		declaration.Public, declaration.RunAliasParent = new(public), parent
		configured, err := f.database.ConfigureService(ctx, f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
			&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
		if err != nil || configured.TrustRevision != f.service.TrustRevision {
			t.Fatal("endpoint configuration changed target trust", err)
		}
		f.service = configured
	}
	assertCurrent := func(run ServiceRunPreparation, want bool) {
		t.Helper()
		var current bool
		if err := f.database.pool.QueryRow(ctx, `SELECT control.service_run_alias_current($1,$2)`,
			run.RunID, run.RunHostname).Scan(&current); err != nil || current != want {
			t.Fatalf("publisher address current = %t, want %t: %v", current, want, err)
		}
	}
	original := start("original-parent")
	if !strings.HasSuffix(original.RunHostname, "."+parent) {
		t.Fatal("initial run has no publisher address under its configured parent")
	}
	assertCurrent(original, true)
	configure(parent, false)
	assertCurrent(original, false)
	configure(parent, true)
	assertCurrent(original, true)
	closeRun(original)
	configure(parent, false)
	private := start("private")
	if private.RunHostname != "" || slices.Contains(private.CertificatePlan.Identifiers, original.RunHostname) {
		t.Fatal("connector-only run obtained an alias or an alias certificate plan")
	}
	closeRun(private)
	nextParent := "replicas." + parent
	configure(nextParent, true)
	moved := start("moved-parent")
	if moved.RunHostname == original.RunHostname || !strings.HasSuffix(moved.RunHostname, "."+nextParent) {
		t.Fatal("changing the authorized parent did not allocate a distinct address")
	}
	assertCurrent(original, false)
	assertCurrent(moved, true)
	closeRun(moved)
	configure(parent, true)
	restored := start("restored-parent")
	if restored.RunHostname != original.RunHostname {
		t.Fatal("restoring the parent changed the publisher's reserved address")
	}
	if err := f.database.RevokePublisherIdentity(ctx, f.project.TeamID, publisher.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	assertCurrent(restored, false)
	var retired bool
	if err := f.database.pool.QueryRow(ctx, `SELECT retired_at IS NOT NULL AND NOT public AND dns_state='removed' AND reusable_after>$2
	    FROM control.service_endpoints WHERE hostname=$1`, original.RunHostname, f.now).Scan(&retired); err != nil || !retired {
		t.Fatal("publisher retirement did not remove the endpoint and retain its quarantine", err)
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
	if !regexp.MustCompile(`^p-[a-z2-7]{26}\.`+regexp.QuoteMeta(parent)+`$`).MatchString(hostname) || !certificate.After(f.now) {
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

func TestIntegrationRunAliasManagedDNSReadinessAndWithdrawal(t *testing.T) {
	f, _, declaration := newRunAliasServiceFixture(t)
	var err error
	f.service, err = f.database.CreateServiceAt(t.Context(), f.project.TeamID, f.project.ActorID, "managed-alias", "managed-alias",
		ServicePlacement{DomainID: f.service.DomainID, DNSAutomation: true}, f.now, f.service.ServiceMetadata, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	lease := registerServiceHTTPAdmissionIngress(t, t.Context(), f, "managed-alias-reader")
	claim := func(hostname string, state ServiceEndpointDNSState) ServiceEndpointDNSWork {
		t.Helper()
		work, found, err := f.database.ClaimServiceEndpointDNSWork(t.Context(), "alias-dns-worker", f.now, time.Minute)
		if err != nil || !found || work.Hostname != hostname || work.State != state {
			t.Fatal("unexpected exact-run DNS work", work, found, err)
		}
		if err := f.database.ValidateServiceEndpointDNSWork(t.Context(), work, f.now); err != nil {
			t.Fatal("current DNS work lost provider authority", err)
		}
		return work
	}
	save := func(work ServiceEndpointDNSWork, state ServiceEndpointDNSState) {
		t.Helper()
		work.State, work.AvailableAt = state, time.Time{}
		if _, err := f.database.SaveServiceEndpointDNSWork(t.Context(), work, f.now); err != nil {
			t.Fatal(err)
		}
	}
	assertReady := func(canonical, alias bool) {
		t.Helper()
		state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 20})
		if err != nil || state.State != "ready" || state.PublicEndpointReady != canonical || state.RunAliasReady != alias {
			t.Fatal("DNS readiness changed run authority or selected the wrong endpoint", state, err)
		}
		routing, err := readIngressServiceRun(t.Context(), f.database, lease.IngressLeaseIdentity, f.service.ID, f.run.RunID, f.now)
		if err != nil || (routing.RunHostname != nil) != alias {
			t.Fatal("ingress advertised an alias before its DNS was ready", err)
		}
	}
	if _, found, err := f.database.ClaimServiceEndpointDNSWork(t.Context(), "early", f.now, time.Minute); err != nil || found {
		t.Fatal("DNS published without a ready run and certificate", found, err)
	}
	f.run = f.publish(t, f.service)
	f.now = f.now.Add(time.Second)
	// claim both names before publishing either; their lexicographic order is
	// not part of the lifecycle contract.
	pending := make(map[string]ServiceEndpointDNSWork)
	for range 2 {
		work, found, err := f.database.ClaimServiceEndpointDNSWork(t.Context(), "alias-dns-worker", f.now, time.Minute)
		if err != nil || !found || work.State != ServiceEndpointDNSPending {
			t.Fatal("ready certificate did not queue both DNS names", found, err)
		}
		pending[work.Hostname] = work
	}
	canonical, canonicalFound := pending[f.service.Endpoint.Hostname]
	alias, aliasFound := pending[f.run.RunHostname]
	if !canonicalFound || !aliasFound || len(pending) != 2 {
		t.Fatal("DNS work did not retain the exact endpoint names")
	}
	// routing keeps ready runs before DNS publication, but excludes their alias.
	assertReady(false, false)
	save(canonical, ServiceEndpointDNSPublished)
	assertReady(true, false)
	parent := declaration.RunAliasParent
	declaration.RunAliasParent = ""
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	if err := f.database.ValidateServiceEndpointDNSWork(t.Context(), alias, f.now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("withdrawn alias retained in-flight DNS authority", err)
	}
	stale := alias
	stale.State, stale.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := f.database.SaveServiceEndpointDNSWork(t.Context(), stale, f.now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("stale DNS worker republished a withdrawn alias", err)
	}
	save(claim(f.run.RunHostname, ServiceEndpointDNSRemoving), ServiceEndpointDNSRemoved)
	assertReady(true, false)
	declaration.RunAliasParent = parent
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	assertReady(true, false)
	// a ready sibling cannot publish this run's pending DNS while this run is
	// unhealthy. it can publish only its own independently allocated name.
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: false, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	sibling := f.publish(t, f.service)
	f.now = f.now.Add(time.Second)
	save(claim(sibling.RunHostname, ServiceEndpointDNSPending), ServiceEndpointDNSPublished)
	if _, found, err := f.database.ClaimServiceEndpointDNSWork(t.Context(), "sibling-cannot-publish", f.now, time.Minute); err != nil || found {
		t.Fatal("a sibling made unhealthy run DNS claimable", found, err)
	}
	assertReady(true, false)
	save(claim(f.run.RunHostname, ServiceEndpointDNSPending), ServiceEndpointDNSPublished)
	assertReady(true, true)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	save(claim(f.run.RunHostname, ServiceEndpointDNSRemoving), ServiceEndpointDNSRemoved)
	var retainedUntil time.Time
	if err := f.database.pool.QueryRow(t.Context(), `SELECT reusable_after FROM control.service_endpoints WHERE hostname=$1`,
		f.run.RunHostname).Scan(&retainedUntil); err != nil || !retainedUntil.After(f.now) {
		t.Fatal("DNS removal released the alias certificate reservation", err)
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
	policies := make(map[string]controlv1.VisitorPolicyUpdate)
	for _, hostname := range []string{"", f.service.Endpoint.Hostname, f.run.RunHostname} {
		policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now, hostname)
		expected := hostname
		if expected == "" {
			expected = f.service.Endpoint.Hostname
		}
		if err != nil || policy.Policy.Hostname != expected || policy.Policy.PublicEndpoint == nil || policy.Policy.PublicEndpoint.Hostname != expected {
			t.Fatal("policy lost its selected hostname", hostname, err)
		}
		if policy.ConfirmationKey == nil {
			t.Fatal("eligible hostname did not receive a snapshot key", hostname)
		}
		policies[hostname] = policy
	}
	canonical, alias := policies[f.service.Endpoint.Hostname], policies[f.run.RunHostname]
	if *canonical.ConfirmationKey != *policies[""].ConfirmationKey {
		t.Fatal("implicit and explicit canonical reads received different keys")
	}
	renew := func() ServiceRunState {
		state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	state := renew()
	if state.AliasPolicyConfirmation == nil || state.PolicyConfirmation == nil ||
		state.AliasPolicyConfirmation.Hostname != f.run.RunHostname || state.AliasPolicyConfirmation.ConfirmationKey != *alias.ConfirmationKey ||
		state.PolicyConfirmation.Hostname != f.service.Endpoint.Hostname || state.PolicyConfirmation.ConfirmationKey != *canonical.ConfirmationKey ||
		*canonical.ConfirmationKey == *alias.ConfirmationKey || !state.AliasPolicyConfirmation.ValidUntil.After(alias.Policy.ValidUntil) {
		t.Fatal("renewal did not confirm two distinct host-bound snapshots")
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
	if state := renew(); state.AliasPolicyConfirmation != nil || state.PolicyConfirmation == nil {
		t.Fatal("alias withdrawal did not isolate canonical renewal")
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
