package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationProjectRetirement(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25600}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.Configuration = workloadConfiguration()
	local := ProjectServiceConfiguration{Protocol: "postgres", Target: "localhost:5432", TargetTLS: &ProjectTargetTLS{Hostname: "cache.internal"}}
	localRequest := r
	localRequest.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"cache": local}}
	localRequest.ServiceDeclarations = map[string]string{"api": "http", "db": "http", "cache": "postgres"}
	localApplied, err := d.ApplyProjectConfiguration(ctx, localRequest)
	if err != nil {
		t.Fatal(err)
	}
	r = selectedProjectRequest(r, "production")
	r.ServiceDeclarations["cache"] = "postgres"
	r.ExpectedRevision = localApplied.Revision
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := d.CreatePreview(ctx, r.TeamID, r.ActorID, "retirement-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = enrollAppliedDeployment(t, d, r, enrollment, now)
	exchange, _ := workloadExchange(t, r, now)
	workload, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	realization := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "cache", WorktreeKey: "checkout", ActorID: r.ActorID, Configuration: local, Now: now}
	resource, err := d.RealizeLocalProjectService(ctx, realization)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(ctx, resource.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	e := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActorID}, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	access := publisherAccess(t, d, publisher, key, "", now)
	run := readyAppliedServiceRun(t, d, access, key, service, leases, now)
	before, err := d.GetProjectStatus(ctx, r.TeamID, r.ProjectKey, r.ActorID, "", now)
	if err != nil {
		t.Fatal(err)
	}
	var observed bool
	for _, p := range before.Publications {
		if p.ServiceRunID == run.RunID {
			observed = p.Ready && p.ReadyPublisherConnections == 2
		}
	}
	if !observed {
		t.Fatal("ready worktree publication missing from project status", before)
	}
	if _, err = d.RetireProject(ctx, r.TeamID, r.ProjectKey, "outsider", applied.Revision, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retirement bypassed management access", err)
	}
	if _, err = d.RetireProject(ctx, r.TeamID, r.ProjectKey, r.ActorID, applied.Revision+1, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("retirement accepted stale revision", err)
	}
	retired, err := d.RetireProject(ctx, r.TeamID, r.ProjectKey, r.ActorID, applied.Revision, now.Add(time.Second))
	if err != nil || retired.RetiredAt == nil || retired.Revision != applied.Revision+1 || len(retired.Services) != 0 || len(retired.Deployments) != 0 || len(retired.Members) != 0 {
		t.Fatal("retired project", retired, err)
	}
	page, err := d.ListProjects(ctx, r.TeamID, r.ActorID, "")
	if err != nil || len(page.Projects) != 0 {
		t.Fatal("retired project remained active", page, err)
	}
	status, err := d.GetProjectStatus(ctx, r.TeamID, r.ProjectKey, r.ActorID, "", now.Add(time.Second))
	if err != nil || status.RetiredAt == nil || len(status.Publications) != 0 || status.ProjectLabel != "storefront" {
		t.Fatal("retired status lost identity or retained publications", status, err)
	}
	assertAppliedPrivateRetired(t, d, r, appliedPrivateResource{record: service, runs: []ServiceRunState{run}})
	if _, err = d.CheckWorkloadService(ctx, workload.Credential, workload.ServiceIDs[0], now.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("retirement retained workload access", err)
	}
	var activeDeployments, activeEnrollments, realizations int
	if err = d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.deployments WHERE team_id=$1 AND project_key=$2 AND deleted_at IS NULL),(SELECT count(*) FROM control.deployment_publisher_enrollments WHERE deployment_id=$3 AND revoked_at IS NULL),(SELECT count(*) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2)`, r.TeamID, r.ProjectKey, applied.Deployments[0].ID).Scan(&activeDeployments, &activeEnrollments, &realizations); err != nil || activeDeployments+activeEnrollments+realizations != 0 {
		t.Fatal("retirement retained assignments", activeDeployments, activeEnrollments, realizations, err)
	}
	if preserved, err := d.GetPreview(ctx, preview.ID); err != nil || preserved.ID != preview.ID {
		t.Fatal("retirement deleted separate preview history", err)
	}
	if retry, err := d.RetireProject(ctx, r.TeamID, r.ProjectKey, r.ActorID, applied.Revision, now.Add(2*time.Second)); err != nil || retry.Revision != retired.Revision || !retry.RetiredAt.Equal(*retired.RetiredAt) {
		t.Fatal("retirement retry changed result", retry, err)
	}
	if _, err = d.RealizeLocalProjectService(ctx, realization); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("local runtime recreated a retired resource", err)
	}
	r.Configuration = ProjectConfiguration{}
	r.Deployment, r.ServiceDeclarations = "local", map[string]string{}
	r.ExpectedRevision = applied.Revision
	if _, err = d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale empty apply reactivated project", err)
	}
	r.ExpectedRevision = retired.Revision
	restored, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || restored.RetiredAt != nil || restored.Revision != retired.Revision+1 {
		t.Fatal("explicit reactivation failed", restored, err)
	}
	page, err = d.ListProjects(ctx, r.TeamID, r.ActorID, "")
	if err != nil || len(page.Projects) != 1 || page.Projects[0].ProjectLabel != "storefront" {
		t.Fatal("reactivation changed saved inventory identity", page, err)
	}
	if _, err = d.RetireProject(ctx, r.TeamID, r.ProjectKey, r.ActorID, applied.Revision, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("old retirement removed reactivated project", err)
	}
}

func TestIntegrationProjectRetirementRacesApply(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "retirement_race")
	r := appliedProjectRequest(t, d, now)
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	service := r.Configuration.Services["web"]
	service.Target = "http://localhost:4000"
	r.Configuration.Services["web"] = service
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := d.RetireProject(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, applied.Revision, now)
		results <- err
	}()
	go func() { <-start; _, err := d.ApplyProjectConfiguration(t.Context(), r); results <- err }()
	close(start)
	var succeeded, stale int
	var failure error
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrProjectConfigurationStale) {
			stale++
		} else {
			failure = errors.Join(failure, err)
		}
	}
	if failure != nil {
		t.Fatal(failure)
	}
	if succeeded != 1 || stale != 1 {
		t.Fatal("concurrent writers did not compare revisions", succeeded, stale)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, r.Deployment)
	if err != nil || current.Revision != applied.Revision+1 {
		t.Fatal("race advanced the project twice", current, err)
	}
	if current.RetiredAt != nil && len(current.Configuration.Services) != 0 {
		t.Fatal("retired marker committed without resource cleanup")
	}
}
