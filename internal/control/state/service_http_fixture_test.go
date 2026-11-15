package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

// review fixtures use actual local services, exact publisher enrollment,
// certificates, and relay claims. no public URL or readiness adapter is involved.
type serviceHTTPFixture struct {
	database *Database
	now      time.Time
	project  ApplyProjectConfigurationRequest
	leases   map[string]RelayLease
	service  ServiceRecord
	run      ServiceRunState
}

func newServiceHTTPFixture(t *testing.T) serviceHTTPFixture {
	t.Helper()
	d, now, _, leases := newPublishRunPrerequisites(t)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	f := serviceHTTPFixture{database: d, now: now, project: appliedProjectRequest(t, d, now), leases: leases}
	f.service = f.local(t, "web", nil)
	return f
}

func (f serviceHTTPFixture) local(t *testing.T, name string, http *config.HTTPService) ServiceRecord {
	t.Helper()
	local, err := f.database.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
		TeamID: f.project.TeamID, ActorID: f.project.ActorID, ProjectKey: f.project.ProjectKey,
		SourceFingerprint: f.project.SourceFingerprint, Service: name, WorktreeKey: "review",
		Configuration: ProjectServiceConfiguration{Target: "localhost:3000", HTTP: http}, Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.database.GetService(t.Context(), local.ServiceID, f.project.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (f serviceHTTPFixture) publish(t *testing.T, service ServiceRecord) ServiceRunState {
	t.Helper()
	enrollment := publisherEnrollment(t, f.database, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID},
		PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: service.ID}, f.now)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access := publisherAccess(t, f.database, publisher, key, "192.0.2.10", f.now)
	return readyAppliedServiceRun(t, f.database, access, key, service, netip.MustParseAddr("192.0.2.10"), f.leases, f.now)
}

func (f serviceHTTPFixture) auth() ServiceHTTPRun {
	return ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		RunID: f.run.RunID, Number: f.run.RunNumber, Token: credentials.ServiceRunToken(f.run.Token)}
}

func (f serviceHTTPFixture) preview(t *testing.T, key string, services ...ServiceRecord) Preview {
	t.Helper()
	preview, err := f.database.CreatePreview(t.Context(), f.project.TeamID, f.project.ActorID, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		preview, err = f.database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
			PreviewID: preview.ID, ServiceID: service.ID, TeamID: f.project.TeamID, IdentityID: f.project.ActorID,
		}, f.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	return preview
}

func (f serviceHTTPFixture) share(t *testing.T, preview, key string, secret []byte, services ...ServiceRecord) Share {
	t.Helper()
	ids := make([]string, len(services))
	for i, service := range services {
		ids[i] = service.ID
	}
	share, err := f.database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview, TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: key, SecretFingerprint: sha256.Sum256(secret), ExpiresAt: f.now.Add(time.Hour),
		ServiceIDs: ids, EntryServiceID: ids[0],
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return share
}

func (f serviceHTTPFixture) browser(t *testing.T, preview, identity string) (BrowserHandoff, ControlSession) {
	t.Helper()
	session := browserTestControlSession(t, f.database, identity, f.now)
	binding := []byte(strings.Repeat("b", 32))
	state, err := f.database.BeginServiceBrowserLogin(t.Context(), f.auth().Subject, preview, "/",
		strings.Repeat("n", 32), strings.Repeat("v", 43), binding, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f.database.ConsumeBrowserLogin(t.Context(), state, binding, f.now)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := f.database.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{
		IdentityID: identity, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: session.RefreshExpiresAt,
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return handoff, session
}
