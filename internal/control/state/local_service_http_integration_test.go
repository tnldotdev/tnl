package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationLocalServiceHTTPPolicySurvivesRealizationAndApply(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {
		Target: "app", HTTP: &config.HTTPService{
			Access: &config.Access{IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: new(100)},
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
		if err := d.serviceHTTPSourceAllowed(ctx, q, id, netip.MustParseAddr(allowed)); err != nil {
			t.Fatal("allowed source rejected", err)
		}
		if err := d.serviceHTTPSourceAllowed(ctx, q, id, netip.MustParseAddr(denied)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("HTTP policy admitted an excluded source", err)
		}
		settings, err := d.serviceHTTPSettings(ctx, q, id)
		if err != nil || settings == nil || settings.Limits == nil || *settings.Limits.Total != total || settings.Readiness != nil {
			t.Fatal("saved policy lost limits or stored application-local behavior", settings, err)
		}
	}
	check(first.ServiceID, "192.0.2.10", "203.0.113.10", 100)
	approved, err := d.GetServiceForPublisher(ctx, first.ServiceID, access, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 100 {
		t.Fatal("local publisher did not receive approved request limits", approved, err)
	}
	run, err := d.PrepareServiceRun(ctx, first.ServiceID, access, "local-http-policy", now, *first.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetLocalServiceHTTPConfiguration(ctx, text(first.ServiceID))
	if err != nil || !before.HttpStorageKeyID.Valid || bytes.Contains(before.HttpConfigurationCiphertext, []byte("192.0.2.10")) {
		t.Fatal("local policy was not encrypted", err)
	}
	revision, err := q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: first.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || retry.ServiceID != first.ServiceID {
		t.Fatal("restart changed local service identity", retry, err)
	}
	after, err := q.GetLocalServiceHTTPConfiguration(ctx, text(first.ServiceID))
	if err != nil {
		t.Fatal(err)
	}
	retriedRevision, err := q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: first.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.HttpConfigurationCiphertext, after.HttpConfigurationCiphertext) || retriedRevision != revision {
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
	changedRevision, err := q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: first.ServiceID})
	if err != nil || changedRevision <= revision {
		t.Fatal("policy change did not invalidate previous visitor authority", changedRevision, err)
	}
	if _, err := d.StartServiceRun(ctx, first.ServiceID, run.RunID, run.RunNumber, access, now); err != nil {
		t.Fatal("request policy change replaced publisher authority or closed its run", err)
	}
	approved, err = d.GetServiceForPublisher(ctx, first.ServiceID, access, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 250 || approved.Endpoint.Port != 0 {
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
	row, err := q.GetLocalServiceHTTPConfiguration(t.Context(), text(first.ServiceID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.SetLocalServiceHTTPConfiguration(t.Context(), controlstatedb.SetLocalServiceHTTPConfigurationParams{ServiceID: text(second.ServiceID), Ciphertext: row.HttpConfigurationCiphertext, StorageKeyID: row.HttpStorageKeyID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.serviceHTTPSettings(t.Context(), q, second.ServiceID); err == nil {
		t.Fatal("another worktree's policy ciphertext was accepted")
	}
	bad, err := d.storageKey.Seal(localServiceHTTPContext(first.ServiceID), []byte(`{"limits":{"rate":{"per":"1s"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.SetLocalServiceHTTPConfiguration(t.Context(), controlstatedb.SetLocalServiceHTTPConfigurationParams{ServiceID: text(first.ServiceID), Ciphertext: bad, StorageKeyID: text(d.storageKey.CurrentID())}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.serviceHTTPSettings(t.Context(), q, first.ServiceID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("malformed stored request limits were accepted", err)
	}
}

func TestIntegrationLocalServiceHTTPPolicyStorageRotation(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "local_http_rotation")
	r := appliedProjectRequest(t, d, now)
	ctx := t.Context()
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: new(100)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	revision, err := q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: local.ServiceID})
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
	row, err := controlstatedb.New(rotating.pool).GetLocalServiceHTTPConfiguration(ctx, text(local.ServiceID))
	if err != nil || row.HttpStorageKeyID.String != rotating.storageKey.CurrentID() {
		t.Fatal("rotation omitted the local policy snapshot", err)
	}
	currentRevision, err := controlstatedb.New(rotating.pool).ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: local.ServiceID})
	if err != nil || currentRevision != revision {
		t.Fatal("storage rotation changed visitor authority", currentRevision, err)
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
}
