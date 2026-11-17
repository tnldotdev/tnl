package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestIntegrationLocalServiceHTTPPolicySurvivesRealizationAndApply(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {
		Target: "app", Traffic: &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2s")}, HTTP: &config.HTTPService{
			RequestBodyIdleTimeout: new(config.Duration(45 * time.Second)),
			Access:                 &config.Access{IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: new(100)},
			Readiness: &config.Readiness{Path: "/health"},
		},
	}}}
	r = selectedProjectRequest(r, "local")
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "web", WorktreeKey: "checkout-a", WorktreeLabel: "feature-a", ActorID: r.ActorID, Configuration: r.Configuration.Services["web"], Now: now}
	first, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	creation := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: first.ServiceID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	check := func(id, allowed, denied string, total int) {
		t.Helper()
		q := controlstatedb.New(d.pool)
		if _, err := d.serviceHTTPSourcePolicy(ctx, q, id, netip.MustParseAddr(allowed)); err != nil {
			t.Fatal("allowed source rejected", err)
		}
		if _, err := d.serviceHTTPSourcePolicy(ctx, q, id, netip.MustParseAddr(denied)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("HTTP policy admitted an excluded source", err)
		}
		settings, err := d.serviceHTTPSettings(ctx, q, id)
		if err != nil || settings == nil || settings.Limits == nil || *settings.Limits.Total != total || settings.Readiness != nil {
			t.Fatal("HTTP policy lost limits or included application-local behavior", settings, err)
		}
	}
	check(first.ServiceID, "192.0.2.10", "203.0.113.10", 100)
	approved, err := d.GetServiceForPublisher(ctx, first.ServiceID, access, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 100 ||
		approved.HTTPRequestBodyIdleTimeout == nil || *approved.HTTPRequestBodyIdleTimeout != "45s" {
		t.Fatal("local publisher did not receive approved request limits", approved, err)
	}
	for _, selection := range []*trafficlimits.Selection{
		{Connections: new(6)},
		{Rate: new(2), RatePer: new("2s")},
		{},
	} {
		if _, err := d.PrepareServiceRun(ctx, first.ServiceID, access, "conflicting-worker", now, ServiceRunRequest{Metadata: *first.Metadata, TrafficSelection: selection}); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("worker traffic replaced or merged with the saved local declaration", err)
		}
	}
	run, err := d.PrepareServiceRun(ctx, first.ServiceID, access, "local-http-policy", now, ServiceRunRequest{Metadata: *first.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	if run.Traffic.Connections != 7 || run.Traffic.Rate != 2 || run.Traffic.RatePer != 2*time.Second {
		t.Fatal("startup before apply did not use its saved traffic settings", run.Traffic)
	}
	retryRequest := ServiceRunRequest{Metadata: *first.Metadata,
		TrafficSelection: &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2000ms")},
		TrafficDefaults:  trafficlimits.Default(), TrafficCeiling: trafficlimits.Ceiling()}
	retryRequest.TrafficDefaults.UploadBytes = 4 << 20
	retryRequest.TrafficCeiling.Connections = 6
	storedRetry, err := d.PrepareServiceRun(ctx, first.ServiceID, access, "local-http-policy", now, retryRequest)
	if err != nil || !reflect.DeepEqual(run, storedRetry) {
		t.Fatal("equivalent worker traffic re-resolved a stored preparation", storedRetry, err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetServiceConfiguration(ctx, first.ServiceID)
	if err != nil || !before.StorageKeyID.Valid || bytes.Contains(before.ConfigurationCiphertext, []byte("192.0.2.10")) {
		t.Fatal("local service configuration was not encrypted", err)
	}
	declaration, err := d.serviceConfiguration(ctx, q, first.ServiceID)
	if err != nil || declaration == nil || declaration.Target != "app" || declaration.HTTP == nil || declaration.HTTP.Readiness == nil || declaration.HTTP.Readiness.Path != "/health" || declaration.Traffic == nil || *declaration.Traffic.Connections != 7 {
		t.Fatal("saved declaration lost target, readiness, or traffic settings", declaration, err)
	}
	revision, err := q.ReadVisitorPolicyRevision(ctx, first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || retry.ServiceID != first.ServiceID {
		t.Fatal("restart changed local service identity", retry, err)
	}
	after, err := q.GetServiceConfiguration(ctx, first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	retriedRevision, err := q.ReadVisitorPolicyRevision(ctx, first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.ConfigurationCiphertext, after.ConfigurationCiphertext) || retriedRevision != revision {
		t.Fatal("unchanged realization rewrote or invalidated HTTP policy", err)
	}
	request.WorktreeKey, request.WorktreeLabel = "checkout-b", "feature-b"
	request.Configuration.HTTP = &config.HTTPService{Access: &config.Access{IP: []string{"203.0.113.10"}}, Limits: &config.WorkLimits{Total: new(250)}}
	second, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || second.ServiceID == first.ServiceID {
		t.Fatal("worktrees share HTTP policy authority", second, err)
	}
	check(first.ServiceID, "192.0.2.10", "203.0.113.10", 100)
	check(second.ServiceID, "203.0.113.10", "192.0.2.10", 250)
	// desired local apply updates every exact realization in one transaction.
	r.Configuration.Services["web"] = request.Configuration
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ServiceID, second.ServiceID} {
		check(id, "203.0.113.10", "192.0.2.10", 250)
	}
	changedRevision, err := q.ReadVisitorPolicyRevision(ctx, first.ServiceID)
	if err != nil || changedRevision <= revision {
		t.Fatal("policy change did not invalidate previous visitor authority", changedRevision, err)
	}
	if _, err := d.StartServiceRun(ctx, first.ServiceID, run.RunID, run.RunNumber, access, now); err != nil {
		t.Fatal("request policy change replaced publisher authority or closed its run", err)
	}
	approved, err = d.GetServiceForPublisher(ctx, first.ServiceID, access, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 250 || approved.Endpoint.Port != 443 || approved.Endpoint.Public {
		t.Fatal("local publisher lost updated request policy or consumed public capacity", approved, err)
	}
	r.ExpectedRevision = applied.Revision
	service := r.Configuration.Services["web"]
	service.HTTP = nil
	r.Configuration.Services["web"] = service
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ServiceID, second.ServiceID} {
		settings, err := d.serviceHTTPSettings(ctx, q, id)
		if err != nil || settings != nil {
			t.Fatal("removing configured policy left a stale local snapshot", settings, err)
		}
	}
}

func TestIntegrationLocalServiceHTTPPolicyCannotBeSubstitutedOrCorrupted(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "web", WorktreeKey: "checkout-a", ActorID: r.ActorID, Configuration: ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.10"}}}}, Now: now}
	first, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.WorktreeKey = "checkout-b"
	second, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	row, err := q.GetServiceConfiguration(t.Context(), first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := q.GetService(t.Context(), first.ServiceID)
	if err != nil || saved.Name == row.Service || row.Service != "web" || !row.LocalOwned || row.DeploymentOwned || !bytes.Equal(saved.ConfigurationCiphertext, row.ConfigurationCiphertext) {
		t.Fatal("service storage lost its logical local service key or provenance", row, err)
	}
	if _, err := q.SetServiceConfiguration(t.Context(), controlstatedb.SetServiceConfigurationParams{ServiceID: second.ServiceID, Ciphertext: row.ConfigurationCiphertext, StorageKeyID: row.StorageKeyID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.serviceHTTPSettings(t.Context(), q, second.ServiceID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another service's policy ciphertext was accepted", err)
	}
	for _, invalid := range []string{
		`{"target":"app","http":{"limits":{"rate":{"per":"1s"}}}}`,
		`{"target":"app","http":{"paths":{"/self":{"service":"web"}}}}`,
		`{"target":"app","public_url":{}}`,
		`{"target":"app"}{}`,
		`null`,
	} {
		bad, err := d.storageKey.Seal(serviceConfigurationContext(first.ServiceID), []byte(invalid))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.SetServiceConfiguration(t.Context(), controlstatedb.SetServiceConfigurationParams{ServiceID: first.ServiceID, Ciphertext: bad, StorageKeyID: text(d.storageKey.CurrentID())}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.serviceHTTPSettings(t.Context(), q, first.ServiceID); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("malformed stored request limits or declaration were accepted", err)
		}
	}
	if _, err := q.SetServiceConfiguration(t.Context(), controlstatedb.SetServiceConfigurationParams{ServiceID: first.ServiceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.serviceConfiguration(t.Context(), q, first.ServiceID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("missing local declaration was accepted", err)
	}
}

func TestIntegrationLocalServiceHTTPPolicyStorageRotation(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "local_http_rotation")
	r := appliedProjectRequest(t, d, now)
	ctx := t.Context()
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", Traffic: &trafficlimits.Selection{Connections: new(7)}, HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: new(100)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := d.CreateServiceAt(ctx, r.TeamID, r.ActorID, "standalone", "rotation-standalone", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	standaloneConfiguration := ProjectServiceConfiguration{
		Target: "https://standalone.internal:8443", TargetTLS: appliedTargetTrust(t, "standalone.internal"),
		Traffic: &trafficlimits.Selection{Connections: new(9)},
		HTTP:    &config.HTTPService{Access: &config.Access{Mode: "anonymous"}, Limits: &config.WorkLimits{Total: new(200)}},
	}
	if err := saveServiceConfigurationForTest(t, d, standalone.ID, standaloneConfiguration); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	revision, err := q.ReadVisitorPolicyRevision(ctx, local.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	standaloneRevision, err := q.ReadVisitorPolicyRevision(ctx, standalone.ID)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotating, err := Open(ctx, databaseURL, key, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{local.ServiceID, standalone.ID} {
		row, err := controlstatedb.New(rotating.pool).GetServiceConfiguration(ctx, id)
		if err != nil || row.StorageKeyID.String != rotating.storageKey.CurrentID() {
			t.Fatal("rotation omitted a service-owned declaration", id, err)
		}
	}
	currentRevision, err := controlstatedb.New(rotating.pool).ReadVisitorPolicyRevision(ctx, local.ServiceID)
	if err != nil || currentRevision != revision {
		t.Fatal("storage rotation changed visitor authority", currentRevision, err)
	}
	currentRevision, err = controlstatedb.New(rotating.pool).ReadVisitorPolicyRevision(ctx, standalone.ID)
	if err != nil || currentRevision != standaloneRevision {
		t.Fatal("storage rotation changed standalone service visitor authority", currentRevision, err)
	}
	reopened, err := Open(ctx, databaseURL, key, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	settings, err := reopened.serviceHTTPSettings(ctx, controlstatedb.New(reopened.pool), local.ServiceID)
	if err != nil || settings == nil || settings.Access.IP[0] != "192.0.2.10/32" || *settings.Limits.Total != 100 {
		t.Fatal("local HTTP policy could not be recovered without the old key", settings, err)
	}
	declaration, err := reopened.serviceConfiguration(ctx, controlstatedb.New(reopened.pool), local.ServiceID)
	if err != nil || declaration == nil || declaration.Target != "app" || declaration.Traffic == nil || *declaration.Traffic.Connections != 7 {
		t.Fatal("full service declaration could not be recovered without the old key", declaration, err)
	}
	declaration, err = reopened.serviceConfiguration(ctx, controlstatedb.New(reopened.pool), standalone.ID)
	if err != nil || declaration == nil || declaration.Target != "standalone.internal:8443" || declaration.TargetTLS == nil || declaration.TargetTLS.Hostname != "standalone.internal" || declaration.Traffic == nil || *declaration.Traffic.Connections != 9 || declaration.HTTP == nil || declaration.HTTP.Access == nil || declaration.HTTP.Access.Mode != "anonymous" || declaration.HTTP.Limits == nil || declaration.HTTP.Limits.Total == nil || *declaration.HTTP.Limits.Total != 200 {
		t.Fatal("service without project provenance lost its declaration during rotation", declaration, err)
	}
}

func TestIntegrationServiceConfigurationWithoutProject(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_configuration")
	r := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	service, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "standalone", "standalone", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	declaration, err := d.serviceConfiguration(ctx, q, service.ID)
	if err != nil || declaration != nil {
		t.Fatal("plain saved service required a project declaration", declaration, err)
	}
	empty, emptyDigest, err := d.GetServiceConfiguration(ctx, service.ID, r.ActingIdentityID)
	if err != nil || empty != nil || !ValidServiceConfigurationDigest(emptyDigest) {
		t.Fatal("declaration-free management read lost its deterministic digest", err)
	}
	mode, err := d.serviceHTTPSourcePolicy(ctx, q, service.ID, netip.MustParseAddr("192.0.2.10"))
	if err != nil || mode != VisitorAccessRestricted {
		t.Fatal("plain saved service lost restricted defaults", mode, err)
	}
	configuration := ProjectServiceConfiguration{
		Target: "https://standalone.internal:8443", TargetTLS: appliedTargetTrust(t, "standalone.internal"),
		Ephemeral: true, RequirePostQuantum: new(true), Public: new(true),
		Traffic: &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2000ms")},
		HTTP: &config.HTTPService{
			Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.10"}},
			Limits: &config.WorkLimits{Total: new(100)}, Readiness: &config.Readiness{Path: "/health"},
		},
	}
	trust, err := appliedServiceTargetTrust(configuration.TargetTLS)
	if err != nil {
		t.Fatal(err)
	}
	metadata := service.ServiceMetadata
	metadata.TLS = trust
	service, err = d.ConfigureService(ctx, service.ID, r.ActingIdentityID, metadata, &configuration, ServiceUpdateConditions{ConfigurationDigest: emptyDigest}, now)
	if err != nil || !service.Ephemeral || !service.RequirePostQuantum || !service.Endpoint.Public {
		t.Fatal(err)
	}
	if err := normalizeAppliedProjectService(service.Name, &configuration, true); err != nil {
		t.Fatal(err)
	}
	declaration, digest, err := d.GetServiceConfiguration(ctx, service.ID, r.ActingIdentityID)
	if err != nil || !reflect.DeepEqual(declaration, &configuration) || !ValidServiceConfigurationDigest(digest) || digest == emptyDigest {
		t.Fatal("service-owned storage lost the full normalized declaration", declaration, err)
	}
	before, err := q.GetServiceConfiguration(ctx, service.ID)
	if err != nil || before.LocalOwned || before.DeploymentOwned || before.AllocationOwned || before.RequiredTemporaryApproval != "" || before.Service != service.Name || len(before.ConfigurationCiphertext) == 0 || !before.StorageKeyID.Valid {
		t.Fatal("service-owned storage required project or worktree provenance", before, err)
	}
	saved, err := q.GetService(ctx, service.ID)
	if err != nil || !bytes.Equal(saved.ConfigurationCiphertext, before.ConfigurationCiphertext) || saved.StorageKeyID != before.StorageKeyID {
		t.Fatal("declaration was not stored on the service", err)
	}
	for _, plaintext := range []string{"standalone.internal", "192.0.2.10", "BEGIN CERTIFICATE", `"traffic"`} {
		if bytes.Contains(saved.ConfigurationCiphertext, []byte(plaintext)) {
			t.Fatal("service declaration was stored without encryption")
		}
	}
	policyKey := service.ID
	revision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	equivalent := configuration
	equivalent.Traffic = &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2s")}
	if retry, err := d.ConfigureService(ctx, service.ID, r.ActingIdentityID, service.ServiceMetadata, &equivalent, ServiceUpdateConditions{ConfigurationDigest: digest}, now); err != nil ||
		retry.ID != service.ID || retry.TrustRevision != service.TrustRevision || retry.EndpointRevision != service.EndpointRevision {
		t.Fatal(err)
	}
	after, err := q.GetServiceConfiguration(ctx, service.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("equivalent declaration rewrote service-owned ciphertext", err)
	}
	if _, repeatedDigest, err := d.GetServiceConfiguration(ctx, service.ID, r.ActingIdentityID); err != nil || repeatedDigest != digest {
		t.Fatal("normalized-equivalent declaration changed its digest", err)
	}
	currentRevision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil || currentRevision != revision {
		t.Fatal("equivalent declaration changed visitor policy", currentRevision, revision, err)
	}
	var associations int
	if err := d.pool.QueryRow(ctx, `SELECT
	    (SELECT count(*) FROM control.local_project_services WHERE service_id=$1)+
	    (SELECT count(*) FROM control.applied_project_services WHERE service_id=$1)`, service.ID).Scan(&associations); err != nil || associations != 0 {
		t.Fatal("declaration storage fabricated project provenance", associations, err)
	}
	corrupt := bytes.Clone(saved.ConfigurationCiphertext)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: corrupt, StorageKeyID: saved.StorageKeyID}); err != nil {
		t.Fatal(err)
	}
	if declaration, err := d.serviceConfiguration(ctx, q, service.ID); !errors.Is(err, ErrServiceAccess) || declaration != nil {
		t.Fatal("corrupt standalone declaration fell back to restricted defaults", declaration, err)
	}
	if declaration, digest, err := d.GetServiceConfiguration(ctx, service.ID, r.ActingIdentityID); !errors.Is(err, ErrServiceAccess) || declaration != nil || digest != "" {
		t.Fatal("protected read returned corrupt declaration data or a usable digest", err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, r.ActingIdentityID, service.ServiceMetadata, &equivalent, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("configure silently replaced corrupt declaration storage", err)
	}
}

func TestIntegrationConfigureServiceDeclarationIsAtomic(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now, ctx := f.database, f.now, t.Context()
	configuration := ProjectServiceConfiguration{Target: "localhost:3000", HTTP: &config.HTTPService{
		Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.10"}},
		Limits: &config.WorkLimits{Total: new(100)},
	}}
	var err error
	f.service, err = d.CreateServiceAt(ctx, f.project.TeamID, f.project.ActorID, "standalone", "standalone",
		ServicePlacement{}, now, ServiceMetadata{}, &configuration)
	if err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	auth := f.auth()
	q := controlstatedb.New(d.pool)
	policyKey := f.service.ID
	revision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
		    'service',(SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
		    'run',(SELECT to_jsonb(r) FROM control.service_runs r WHERE id=$2),
		    'policy',(SELECT revision FROM control.visitor_policies WHERE resource_id=$1),
		    'endpoints',(SELECT jsonb_agg(to_jsonb(e) ORDER BY hostname) FROM control.service_endpoints e WHERE service_id=$1),
		    'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY cursor) FROM control.service_audit_events a WHERE service_id=$1))::text`,
			f.service.ID, f.run.RunID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	changed := ProjectServiceConfiguration{Target: "localhost:4000", HTTP: &config.HTTPService{
		Access: &config.Access{Mode: "restricted", IP: []string{"203.0.113.10"}},
		Limits: &config.WorkLimits{Total: new(101)},
	}}
	before := snapshot()
	denied := changed
	denied.Hostname = "outside.invalid"
	if _, err := d.ConfigureService(ctx, f.service.ID, f.project.ActorID, f.service.ServiceMetadata, &denied, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("configure accepted a hostname outside domain authority", err)
	}
	if snapshot() != before {
		t.Fatal("failed endpoint authorization committed declaration, policy, metadata, or audit changes")
	}
	input, _ := json.Marshal(changed)
	updated, err := d.ConfigureService(ctx, f.service.ID, f.project.ActorID, f.service.ServiceMetadata, &changed, ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
	afterInput, _ := json.Marshal(changed)
	if err != nil || updated.ID != f.service.ID || updated.TrustRevision != f.service.TrustRevision ||
		updated.EndpointRevision != f.service.EndpointRevision || !bytes.Equal(input, afterInput) {
		t.Fatal("declaration edit replaced identity, changed trust/placement, or mutated caller input", err)
	}
	nextRevision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil || nextRevision <= revision {
		t.Fatal("HTTP policy and limits did not invalidate current visitor permissions", err)
	}
	if _, err := d.serviceHTTPSourcePolicy(ctx, q, updated.ID, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old visitor source policy remained authorized", err)
	}
	if mode, err := d.serviceHTTPSourcePolicy(ctx, q, updated.ID, netip.MustParseAddr("203.0.113.10")); err != nil || mode != VisitorAccessRestricted {
		t.Fatal("new visitor policy did not take effect", err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), revision, now); err != nil {
		t.Fatal("policy edit ended the existing run instead of refreshing its permission snapshot", err)
	}
	settings, err := d.serviceHTTPSettings(ctx, q, updated.ID)
	if err != nil || settings == nil || settings.Limits == nil || *settings.Limits.Total != 101 {
		t.Fatal("updated per-run request limits were not projected", err)
	}
	var active bool
	if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NULL AND id=$2 AND run_number=$3 FROM control.service_runs WHERE service_id=$1`,
		updated.ID, f.run.RunID, f.run.RunNumber).Scan(&active); err != nil || !active {
		t.Fatal("request-limit edit replaced the run and reset its budget lifetime", err)
	}
	stored, err := q.GetServiceConfiguration(ctx, updated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, updated.ServiceMetadata, &changed, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); err != nil {
		t.Fatal("lost-response retry failed", err)
	}
	retried, err := q.GetServiceConfiguration(ctx, updated.ID)
	if err != nil || !reflect.DeepEqual(stored, retried) {
		t.Fatal("exact retry rewrote encrypted declaration", err)
	}
	if current, err := q.ReadVisitorPolicyRevision(ctx, policyKey); err != nil || current != nextRevision {
		t.Fatal("exact retry invalidated permissions again", err)
	}
	changed.TargetTLS = appliedTargetTrust(t, "replacement.internal")
	trust, err := appliedServiceTargetTrust(changed.TargetTLS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, updated.ServiceMetadata, &changed, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("explicit declaration silently replaced contradictory target trust", err)
	}
	metadata := updated.ServiceMetadata
	metadata.TLS = trust
	trusted, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, metadata, &changed, ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
	if err != nil || trusted.TrustRevision != updated.TrustRevision+1 || trusted.EndpointRevision != updated.EndpointRevision {
		t.Fatal("target trust did not advance independently of endpoint placement", err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(ctx, auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old run retained visitor permission after target-trust replacement", err)
	}
	if _, err := d.ConfigureService(ctx, updated.ID, f.project.ActorID, metadata, &changed, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale expected trust revision was accepted", err)
	}
}

func TestIntegrationServiceConfigurationRejectsConflictingSources(t *testing.T) {
	d, now, project, applied, service := serviceReleaseProject(t, "http", false)
	ctx := t.Context()
	q := controlstatedb.New(d.pool)
	configuration, err := d.serviceConfiguration(ctx, q, service.ID)
	if err != nil || configuration == nil {
		t.Fatal("remote deployment declaration was unavailable", err)
	}
	stored, err := q.GetServiceConfiguration(ctx, service.ID)
	if err != nil || stored.LocalOwned || !stored.DeploymentOwned || stored.ConfigurationCiphertext != nil || stored.StorageKeyID.Valid {
		t.Fatal("remote deployment declaration was copied onto the service", stored, err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, project.ActorID, service.ServiceMetadata, configuration, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("explicit configuration replaced the remote deployment's declaration source", err)
	}
	remote, err := q.GetDeploymentServiceConfiguration(ctx, text(service.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := saveServiceConfigurationForTest(t, d, service.ID, *configuration); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("service-owned save overrode remote deployment authority", err)
	}
	stillRemote, err := q.GetDeploymentServiceConfiguration(ctx, text(service.ID))
	if err != nil || !reflect.DeepEqual(remote, stillRemote) {
		t.Fatal("rejected service-owned save rewrote remote deployment configuration", err)
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := d.storageKey.Seal(serviceConfigurationContext(service.ID), encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, ciphertext := range [][]byte{sealed, []byte("corrupt")} {
		if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: ciphertext, StorageKeyID: text(d.storageKey.CurrentID())}); err != nil {
			t.Fatal(err)
		}
		if declaration, err := d.serviceConfiguration(ctx, q, service.ID); !errors.Is(err, ErrServiceAccess) || declaration != nil {
			t.Fatal("conflicting service ciphertext shadowed or fell back to remote configuration", declaration, err)
		}
	}
	if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID}); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.serviceConfiguration(ctx, q, service.ID)
	if err != nil || !reflect.DeepEqual(configuration, recovered) {
		t.Fatal("remote configuration no longer remained its sole declaration source", recovered, err)
	}
	// a retained binding cannot fall back to restricted defaults when its
	// deployment is gone, even though there is no service-owned ciphertext.
	if _, err := d.pool.Exec(ctx, `UPDATE control.deployments SET deleted_at=$2 WHERE id=$1`, applied.Deployments[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if declaration, err := d.serviceConfiguration(ctx, q, service.ID); !errors.Is(err, ErrServiceAccess) || declaration != nil {
		t.Fatal("missing remote owner fell back to a plain saved service", declaration, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.deployments SET deleted_at=NULL WHERE id=$1`, applied.Deployments[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,service_id,created_by_identity_id)
	    VALUES($1,$2,$3,'app','conflicting-checkout',$4,$5)`, project.TeamID, project.ProjectKey, project.SourceFingerprint, service.ID, project.ActorID); err != nil {
		t.Fatal(err)
	}
	for _, ciphertext := range [][]byte{nil, sealed} {
		key := text(d.storageKey.CurrentID())
		if ciphertext == nil {
			key = nullableText("")
		}
		if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: ciphertext, StorageKeyID: key}); err != nil {
			t.Fatal(err)
		}
		if declaration, err := d.serviceConfiguration(ctx, q, service.ID); !errors.Is(err, ErrServiceAccess) || declaration != nil {
			t.Fatal("conflicting local and deployment ownership was accepted", declaration, err)
		}
	}
}

func TestIntegrationAllocatedServiceConfigurationIsImmutable(t *testing.T) {
	for _, mode := range []string{"restricted", "anonymous"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentPublicationFixture(t)
			_, _, access, _ := f.approve(t, nil, "anonymous")
			request := f.allocation(t, access)
			request.Configuration = ProjectServiceConfiguration{
				Target: "https://app.internal:3000", TargetTLS: &ProjectTargetTLS{Hostname: "app.internal"},
				RequirePostQuantum: new(true),
				Traffic:            &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2s")},
				HTTP: &config.HTTPService{
					Access: &config.Access{Mode: mode, IP: []string{"192.0.2.0/24"}},
					Limits: &config.WorkLimits{Total: new(10)},
				},
			}
			ctx := t.Context()
			service, err := f.d.AllocateDeploymentPublication(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			q := controlstatedb.New(f.d.pool)
			before, err := q.GetServiceConfiguration(ctx, service.ID)
			if err != nil || !before.AllocationOwned || before.LocalOwned || before.DeploymentOwned || before.RequiredTemporaryApproval != mode {
				t.Fatal("declaration storage lost actual allocation ownership or required approval", before, err)
			}
			declaration, err := f.d.serviceConfiguration(ctx, q, service.ID)
			if err != nil || declaration == nil {
				t.Fatal("allocated declaration was unavailable", err)
			}
			encoded, err := json.Marshal(declaration)
			if err != nil {
				t.Fatal(err)
			}
			policyKey := service.ID
			revision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
			if err != nil {
				t.Fatal(err)
			}
			var equivalent ProjectServiceConfiguration
			if err := json.Unmarshal(encoded, &equivalent); err != nil {
				t.Fatal(err)
			}
			equivalent.Target = "https://app.internal:3000"
			equivalent.Traffic.RatePer = new("2000ms")
			if err := saveServiceConfigurationForTest(t, f.d, service.ID, equivalent); err != nil {
				t.Fatal("exact normalized allocation retry was rejected", err)
			}
			for _, edit := range []struct {
				name   string
				change func(*ProjectServiceConfiguration)
			}{
				{"target", func(s *ProjectServiceConfiguration) { s.Target = "other.internal:3000" }},
				{"target-tls", func(s *ProjectServiceConfiguration) { s.TargetTLS = &ProjectTargetTLS{Hostname: "other.internal"} }},
				{"name", func(s *ProjectServiceConfiguration) { s.Name = "other" }},
				{"public", func(s *ProjectServiceConfiguration) { s.Public = new(false) }},
				{"ephemeral", func(s *ProjectServiceConfiguration) { s.Ephemeral = false }},
				{"post-quantum", func(s *ProjectServiceConfiguration) { s.RequirePostQuantum = new(false) }},
				{"traffic", func(s *ProjectServiceConfiguration) { s.Traffic.Connections = new(8) }},
				{"request-budget", func(s *ProjectServiceConfiguration) { s.HTTP.Limits.Total = new(11) }},
				{"ip", func(s *ProjectServiceConfiguration) { s.HTTP.Access.IP = []string{"198.51.100.0/24"} }},
				{"mode", func(s *ProjectServiceConfiguration) {
					s.HTTP.Access.Mode = "anonymous"
					if mode == "anonymous" {
						s.HTTP.Access.Mode = "restricted"
					}
				}},
				{"readiness", func(s *ProjectServiceConfiguration) { s.HTTP.Readiness = &config.Readiness{Path: "/health"} }},
			} {
				t.Run(edit.name, func(t *testing.T) {
					var changed ProjectServiceConfiguration
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					edit.change(&changed)
					if err := saveServiceConfigurationForTest(t, f.d, service.ID, changed); !errors.Is(err, ErrServiceConflict) {
						t.Fatal("changed allocated declaration was not rejected", err)
					}
				})
			}
			after, err := q.GetServiceConfiguration(ctx, service.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("allocation retry or rejected edit changed its stored declaration", err)
			}
			currentRevision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
			if err != nil || currentRevision != revision {
				t.Fatal("allocation retry or rejected edit changed visitor policy", currentRevision, revision, err)
			}
		})
	}
}

func TestIntegrationAllocatedServiceConfigurationFailsClosed(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, access, _ := f.approve(t, nil, "anonymous")
	for _, damage := range []string{
		"missing", "corrupt", "malformed", "restricted-to-anonymous", "anonymous-to-restricted",
		"local-owner", "deployment-owner",
	} {
		t.Run(damage, func(t *testing.T) {
			ctx := t.Context()
			q := controlstatedb.New(f.d.pool)
			request := f.allocation(t, access)
			if damage == "anonymous-to-restricted" {
				request.Configuration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
			}
			service, err := f.d.AllocateDeploymentPublication(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			original, err := f.d.serviceConfiguration(ctx, q, service.ID)
			if err != nil || original == nil {
				t.Fatal("allocation creation did not save a valid declaration before association", err)
			}
			// the default restricted mode is valid without an explicit HTTP block.
			if damage != "anonymous-to-restricted" && original.HTTP != nil {
				t.Fatal("allocation invented HTTP settings for its default mode")
			}
			switch damage {
			case "missing":
				if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID}); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				stored, err := q.GetServiceConfiguration(ctx, service.ID)
				if err != nil {
					t.Fatal(err)
				}
				corrupt := bytes.Clone(stored.ConfigurationCiphertext)
				corrupt[len(corrupt)-1] ^= 1
				if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: corrupt, StorageKeyID: stored.StorageKeyID}); err != nil {
					t.Fatal(err)
				}
			case "malformed", "restricted-to-anonymous", "anonymous-to-restricted":
				encoded := []byte(`null`)
				if damage != "malformed" {
					changed := *original
					changed.HTTP = nil
					if damage == "restricted-to-anonymous" {
						changed.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
					}
					encoded, err = json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
				}
				sealed, err := f.d.storageKey.Seal(serviceConfigurationContext(service.ID), encoded)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: sealed, StorageKeyID: text(f.d.storageKey.CurrentID())}); err != nil {
					t.Fatal(err)
				}
			case "local-owner":
				if _, err := f.d.pool.Exec(ctx, `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,service_id,created_by_identity_id)
				    VALUES($1,$2,$3,$4,'conflicting-allocation',$5,$6)`, f.project.TeamID, f.project.ProjectKey, f.project.SourceFingerprint, service.Name, service.ID, f.project.ActorID); err != nil {
					t.Fatal(err)
				}
			case "deployment-owner":
				if _, err := f.d.pool.Exec(ctx, `UPDATE control.applied_project_services SET service_id=$1
				    WHERE deployment_id=$2 AND service='web'`, service.ID, f.production.ID); err != nil {
					t.Fatal(err)
				}
			}
			before, err := q.GetServiceConfiguration(ctx, service.ID)
			if err != nil || !before.AllocationOwned || before.LocalOwned != (damage == "local-owner") || before.DeploymentOwned != (damage == "deployment-owner") {
				t.Fatal("storage query lost the actual allocation association or conflicting owner", before, err)
			}
			required := "restricted"
			if damage == "anonymous-to-restricted" {
				required = "anonymous"
			}
			if before.RequiredTemporaryApproval != required {
				t.Fatal("declaration damage changed immutable required approval", before.RequiredTemporaryApproval)
			}
			if declaration, err := f.d.serviceConfiguration(ctx, q, service.ID); !errors.Is(err, ErrServiceAccess) || declaration != nil {
				t.Fatal("damaged allocated declaration or conflicting ownership was accepted", declaration, err)
			}
			if _, err := f.d.serviceHTTPSourcePolicy(ctx, q, service.ID, netip.MustParseAddr("192.0.2.10")); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("damaged allocation fell back to restricted visitor defaults", err)
			}
			if err := saveServiceConfigurationForTest(t, f.d, service.ID, *original); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("save repaired or adopted an invalid allocated declaration", err)
			}
			after, err := q.GetServiceConfiguration(ctx, service.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("denied save changed allocation declaration or ownership", err)
			}
		})
	}
}

func saveServiceConfigurationForTest(t *testing.T, d *Database, service string, configuration ProjectServiceConfiguration) error {
	t.Helper()
	ctx := t.Context()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackTestTransaction(t, tx)
	q := controlstatedb.New(tx)
	saved, err := q.GetService(ctx, service)
	if err != nil {
		return err
	}
	if !saved.TeamID.Valid || saved.GuestID.Valid {
		return ErrServiceAccess
	}
	if _, err := q.LockLocalTeamForMutation(ctx, saved.TeamID.String); err != nil {
		return err
	}
	if _, err := q.LockService(ctx, service); err != nil {
		return err
	}
	if err := d.saveServiceConfiguration(ctx, tx, service, configuration); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func TestIntegrationLocalServiceConfigurationEditsKeepHTTPPolicyRevision(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_configuration_edits")
	r := appliedProjectRequest(t, d, now)
	ctx := t.Context()
	request := RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{
			Access: &config.Access{IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: new(100)},
			Readiness: &config.Readiness{Path: "/health"},
		}},
	}
	first, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	policyKey := first.ServiceID
	revision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	before, err := q.GetServiceConfiguration(ctx, first.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []struct {
		name   string
		change func(*ProjectServiceConfiguration)
	}{
		{"target", func(s *ProjectServiceConfiguration) { s.Target = "localhost:3001" }},
		{"traffic", func(s *ProjectServiceConfiguration) { s.Traffic = &trafficlimits.Selection{Connections: new(7)} }},
		{"readiness", func(s *ProjectServiceConfiguration) { s.HTTP.Readiness.Path = "/ready" }},
		{"mount", func(s *ProjectServiceConfiguration) {
			s.HTTP.Paths = map[string]config.PathMount{"/api": {Service: "api"}}
		}},
	} {
		t.Run(edit.name, func(t *testing.T) {
			edit.change(&request.Configuration)
			realized, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || realized.ServiceID != first.ServiceID {
				t.Fatal("declaration edit replaced the local service", realized, err)
			}
			after, err := q.GetServiceConfiguration(ctx, first.ServiceID)
			if err != nil || bytes.Equal(before.ConfigurationCiphertext, after.ConfigurationCiphertext) {
				t.Fatal("changed declaration was not saved", err)
			}
			got, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
			if err != nil || got != revision {
				t.Fatal("non-policy declaration edit invalidated HTTP permissions", got, revision, err)
			}
			before = after
		})
	}
	declaration, err := d.serviceConfiguration(ctx, q, first.ServiceID)
	if err != nil || declaration == nil || declaration.Target != "localhost:3001" || declaration.Traffic == nil || declaration.HTTP == nil || declaration.HTTP.Readiness == nil || declaration.HTTP.Readiness.Path != "/ready" || declaration.HTTP.Paths["/api"].Service != "api" {
		t.Fatal("full declaration edits were not retained", declaration, err)
	}
	for _, change := range []func(*config.HTTPService){
		func(h *config.HTTPService) { h.Limits.Total = new(101) },
		func(h *config.HTTPService) { h.Access.Mode = "anonymous" },
	} {
		change(request.Configuration.HTTP)
		if _, err := d.RealizeLocalProjectService(ctx, request); err != nil {
			t.Fatal(err)
		}
		next, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
		if err != nil || next <= revision {
			t.Fatal("changed HTTP access or request limits did not invalidate permissions", next, revision, err)
		}
		revision = next
	}
}

func TestIntegrationSavedServiceConfigurationTraffic(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, project, applied, service := serviceReleaseProject(t, protocol, false)
			ctx := t.Context()
			declaration := project.Configuration.Services["app"]
			declaration.Traffic = &trafficlimits.Selection{Connections: new(4), Rate: new(2), RatePer: new("60s")}
			project.Configuration.Services["app"] = declaration
			project.ExpectedRevision = applied.Revision
			if _, err := d.ApplyProjectConfiguration(ctx, project); err != nil {
				t.Fatal(err)
			}
			publisher := serviceReleasePublisher(t, d, project, now)
			for _, selected := range []*trafficlimits.Selection{
				{Connections: new(3)},
				{UploadBytes: new(int64(4 << 20))},
				{},
			} {
				if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "conflicting-worker", now, ServiceRunRequest{Metadata: service.ServiceMetadata, TrafficSelection: selected}); !errors.Is(err, ErrServiceConflict) {
					t.Fatal("worker traffic replaced or merged with the saved deployment declaration", err)
				}
			}
			request := ServiceRunRequest{Metadata: service.ServiceMetadata}
			prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "saved-traffic", now, request)
			if err != nil || prepared.Traffic.Connections != 4 || prepared.Traffic.Rate != 2 || prepared.Traffic.RatePer != time.Minute {
				t.Fatal("run did not use the saved deployment traffic selection", prepared, err)
			}
			request.TrafficSelection = &trafficlimits.Selection{Connections: new(4), Rate: new(2), RatePer: new("60000ms")}
			request.TrafficDefaults, request.TrafficCeiling = trafficlimits.Default(), trafficlimits.Ceiling()
			request.TrafficDefaults.UploadBytes = 4 << 20
			request.TrafficCeiling.Connections = 3
			retry, err := d.PrepareServiceRun(ctx, service.ID, publisher, "saved-traffic", now, request)
			if err != nil || !reflect.DeepEqual(prepared, retry) {
				t.Fatal("saved declaration retry re-resolved traffic approval", retry, err)
			}
			if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "new-traffic", now, request); !errors.Is(err, ErrTrafficSelection) {
				t.Fatal("new preparation ignored current operator ceilings", err)
			}
		})
	}
}

func TestIntegrationLocalServiceApplyRejectsCapturedEndpointChanges(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration.Services["web"] = ProjectServiceConfiguration{
		Target: "https://upstream.internal:8443", TargetTLS: appliedTargetTrust(t, "upstream.internal"),
		Traffic: &trafficlimits.Selection{Connections: new(7)},
	}
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Configuration: r.Configuration.Services["web"], Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	creation := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: local.ServiceID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, local.ServiceID, publisher, "captured-endpoint", now, ServiceRunRequest{Metadata: *local.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, local.ServiceID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	beforeService, err := q.GetService(ctx, local.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	runKey := controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: local.ServiceID}
	beforeRun, err := q.LockServiceRun(ctx, runKey)
	if err != nil {
		t.Fatal(err)
	}
	beforeConfiguration, err := q.GetServiceConfiguration(ctx, local.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"upstream.internal", "BEGIN CERTIFICATE", `"traffic"`} {
		if bytes.Contains(beforeConfiguration.ConfigurationCiphertext, []byte(value)) {
			t.Fatal("full local declaration was stored without encryption")
		}
	}
	for _, selector := range []string{"hostname", "domain"} {
		t.Run(selector, func(t *testing.T) {
			next := r
			next.ExpectedRevision = applied.Revision
			next.Configuration, _, err = NormalizeProjectConfiguration(r.Configuration)
			if err != nil {
				t.Fatal(err)
			}
			service := next.Configuration.Services["web"]
			service.Target = "https://replacement.internal:9443"
			service.TargetTLS = appliedTargetTrust(t, "replacement.internal")
			service.Traffic = &trafficlimits.Selection{Connections: new(9)}
			if selector == "hostname" {
				service.Hostname = "replacement." + local.Hostname
			} else {
				service.DomainID = mustOpaqueID(t, opaqueid.DomainPrefix)
			}
			next.Configuration.Services["web"] = service
			if _, err := d.ApplyProjectConfiguration(ctx, next); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("local apply accepted a different captured endpoint", err)
			}
			afterService, err := q.GetService(ctx, local.ServiceID)
			if err != nil || !reflect.DeepEqual(beforeService, afterService) {
				t.Fatal("rejected selection changed the service endpoint or target trust", err)
			}
			afterRun, err := q.LockServiceRun(ctx, runKey)
			if err != nil || !reflect.DeepEqual(beforeRun, afterRun) {
				t.Fatal("rejected selection changed the service run", err)
			}
			afterConfiguration, err := q.GetServiceConfiguration(ctx, local.ServiceID)
			if err != nil || !reflect.DeepEqual(beforeConfiguration, afterConfiguration) {
				t.Fatal("rejected selection changed the encrypted local declaration", err)
			}
			status, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "local")
			if err != nil || status.Revision != applied.Revision || status.ConfigurationHash != applied.ConfigurationHash {
				t.Fatal("rejected selection changed saved project settings", err)
			}
		})
	}
}
