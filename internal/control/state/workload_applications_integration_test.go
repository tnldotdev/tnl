package state

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func appliedWorkloadApplication(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, name string) ApplicationRegistration {
	t.Helper()
	var app ApplicationRegistration
	if err := d.pool.QueryRow(t.Context(), `SELECT app.id,app.team_id,app.name,app.ownership FROM control.workload_applications binding JOIN control.publisher_identities app ON app.id=binding.publisher_identity_id WHERE binding.team_id=$1 AND binding.project_key=$2 AND binding.workload_name=$3 AND binding.revoked_at IS NULL`, r.TeamID, r.ProjectKey, name).Scan(&app.ID, &app.TeamID, &app.Name, &app.Ownership); err != nil {
		t.Fatal(err)
	}
	grants, err := controlstatedb.New(d.pool).ListPublisherGrants(t.Context(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if !g.RevokedAt.Valid {
			app.Grants = append(app.Grants, ApplicationGrant{ID: g.ID, Operation: ApplicationOperation(g.Operation), Scope: scopeFromGrant(r.TeamID, g)})
		}
	}
	return app
}

func workloadApplicationAccess(t *testing.T, d *Database, app ApplicationRegistration, session WorkloadSession, key ed25519.PrivateKey, grant string, now time.Time) (PublisherAccess, error) {
	t.Helper()
	var keyID string
	if err := d.pool.QueryRow(t.Context(), `SELECT id FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND workload_session_id=$2`, app.ID, session.ID).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	proof, err := publisherproof.Sign(app.ID, keyID, grant, publisherTestAudience, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return d.ExchangePublisherAssertion(t.Context(), app.ID, grant, publisherTestAudience, proof, "", now)
}

func TestIntegrationWorkloadApplyRegistersUnifiedApplicationGrants(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	urlRequest := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, urlRequest, now)
	r := ApplyProjectConfigurationRequest{TeamID: url.TeamID, ActorID: urlRequest.ActingIdentityID, ProjectKey: "unified", SourceFingerprint: strings.Repeat("a", 64), Configuration: workloadConfiguration(), Now: now}
	p := r.Configuration.Workloads["test"]
	p.Grants.Visit = append(p.Grants.Visit, config.WorkloadResource{PublicURL: new(url.CanonicalHostname)})
	p.Grants.Publish = []config.WorkloadResource{{Service: new("api")}, {PublicURL: new(url.CanonicalHostname)}}
	p.Grants.Allocate = []config.WorkloadAllocation{{Domain: "tunnels.example.test"}}
	r.Configuration.Workloads["test"] = p
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	app := appliedWorkloadApplication(t, d, r, "test")
	if app.Ownership != "member" || len(app.Grants) != 6 {
		t.Fatal("apply did not register one explicit application", app)
	}
	if retried, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil || retried.Revision != applied.Revision {
		t.Fatal("lost apply response changed the revision", err)
	}
	if retry := appliedWorkloadApplication(t, d, r, "test"); !reflect.DeepEqual(app, retry) {
		t.Fatal("apply retry changed application or grants")
	}
	var persistent int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND workload_session_id IS NULL`, app.ID).Scan(&persistent); err != nil || persistent != 0 {
		t.Fatal("federation setup created an unused permanent credential", err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || len(session.ServiceIDs) != 2 {
		t.Fatal("application visit inventory changed", err)
	}
	var removed []ApplicationGrant
	for _, grant := range app.Grants {
		access, err := workloadApplicationAccess(t, d, app, session, key, grant.ID, now)
		if err != nil || access.ID != app.ID || access.Operation != grant.Operation || !access.Until.Equal(session.LeaseExpiresAt) {
			t.Fatal("platform session did not use the saved application grant", err)
		}
		if grant.Operation == ApplicationAllocate {
			if access.Scope.Namespace == "tunnels.example.test" || !strings.HasSuffix(access.Scope.Namespace, ".tunnels.example.test") {
				t.Fatal("allocation escaped its approved member namespace", access.Scope.Namespace)
			}
		}
		if grant.Operation != ApplicationVisit {
			removed = append(removed, grant)
		}
	}
	// narrowing and later restoration must not upgrade the existing job's key.
	p.Grants.Publish = nil
	p.Grants.Allocate = nil
	r.Configuration.Workloads["test"] = p
	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(time.Second)
	narrowed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range removed {
		if _, err := workloadApplicationAccess(t, d, app, session, key, grant.ID, r.Now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("removed operation survived apply", err)
		}
	}
	p.Grants.Publish = []config.WorkloadResource{{Service: new("api")}, {PublicURL: new(url.CanonicalHostname)}}
	p.Grants.Allocate = []config.WorkloadAllocation{{Domain: "tunnels.example.test"}}
	r.Configuration.Workloads["test"] = p
	r.ExpectedRevision = narrowed.Revision
	r.Now = now.Add(2 * time.Second)
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	restored := appliedWorkloadApplication(t, d, r, "test")
	if restored.ID != app.ID {
		t.Fatal("grant edits replaced the application identity")
	}
	for _, grant := range restored.Grants {
		if grant.Operation != ApplicationVisit {
			if _, err := workloadApplicationAccess(t, d, app, session, key, grant.ID, r.Now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("restoration upgraded an existing job", err)
			}
		}
	}
}

func TestIntegrationWorkloadApplyPublishOnlyAndAtomicSelectorFailure(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_publish_only")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	p := r.Configuration.Workloads["test"]
	p.Grants = config.WorkloadGrants{Publish: []config.WorkloadResource{{Service: new("api")}}}
	r.Configuration.Workloads["test"] = p
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	app := appliedWorkloadApplication(t, d, r, "test")
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil || len(session.ServiceIDs) != 0 {
		t.Fatal("publish-only session required visitor authority", err)
	}
	if _, err := workloadApplicationAccess(t, d, app, session, key, app.Grants[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if services, err := d.ListWorkloadServices(t.Context(), session.Credential, now); err != nil || len(services) != 0 {
		t.Fatal("publisher grant became visit authority", err)
	}
	p.Grants.Visit = []config.WorkloadResource{{PublicURL: new("not-saved.example.test")}}
	r.Configuration.Workloads["test"] = p
	r.ExpectedRevision = applied.Revision
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrApplicationRegistration) {
		t.Fatal("unknown saved URL was accepted", err)
	}
	if current := appliedWorkloadApplication(t, d, r, "test"); !reflect.DeepEqual(app, current) {
		t.Fatal("failed apply changed existing grants")
	}
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT revision FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&revision); err != nil || revision != applied.Revision {
		t.Fatal("failed apply advanced the project revision", err)
	}
}

func TestIntegrationWorkloadApplyOwnershipChangeReplacesDelegation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_ownership")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	memberApp := appliedWorkloadApplication(t, d, r, "test")
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Configuration.Workloads["test"]
	p.Ownership = "team"
	r.Configuration.Workloads["test"] = p
	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(time.Second)
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	teamApp := appliedWorkloadApplication(t, d, r, "test")
	if teamApp.ID == memberApp.ID || teamApp.Ownership != "team" {
		t.Fatal("ownership change silently transferred the existing delegation")
	}
	if _, err := d.ExchangeWorkload(t.Context(), exchange, r.Now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("ownership change retained the old source session", err)
	}
	if _, err := workloadApplicationAccess(t, d, memberApp, session, key, memberApp.Grants[0].ID, r.Now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("old member app retained rights", err)
	}
	// team ownership must not turn into the setup person's ongoing session.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, r.ActorID, r.Now); err != nil {
		t.Fatal(err)
	}
	newExchange, newKey := workloadExchange(t, r, now.Add(2*time.Second))
	newExchange.Execution.GitHub.CheckRunID = "99999"
	newExchange.Execution.GitHub.JTI = "team-job"
	signWorkloadRequest(&newExchange, newKey)
	teamSession, err := d.ExchangeWorkload(t.Context(), newExchange, now.Add(2*time.Second))
	if err != nil {
		t.Fatal("team delegation depended on the setup person", err)
	}
	if _, err := workloadApplicationAccess(t, d, teamApp, teamSession, newKey, teamApp.Grants[0].ID, now.Add(2*time.Second)); err != nil {
		t.Fatal("team app lost its explicit delegation", err)
	}
}
