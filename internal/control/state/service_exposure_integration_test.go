package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPerServiceExposureKeepsPrivateRunsAndCapacity(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"api": {Target: "http://app.internal:3000", Public: new(true)},
		"db":  {Protocol: "postgres", Target: "db.internal:5432", Public: new(false)},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]AppliedProjectService{}
	for _, service := range applied.Services {
		byName[service.Service] = service
	}
	if !byName["api"].Public || byName["api"].Port != 25443 || byName["db"].Public || byName["db"].Port != 0 {
		t.Fatal("mixed exposure allocated the wrong public bindings", applied.Services)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	runs := map[string]ServiceRunPreparation{}
	publishers := map[string]PublisherIdentity{}
	grants := map[string]string{}
	for _, assignment := range replica.assignments.Services {
		if assignment.Configuration.Public != nil {
			t.Fatal("control reachability leaked into publisher lifecycle settings")
		}
		access := deploymentAssignmentAccess(t, d, replica, assignment, now)
		prepared, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "mixed-"+assignment.Service, now, ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision})
		if err != nil {
			t.Fatal(err)
		}
		runs[assignment.Service], publishers[assignment.Service], grants[assignment.Service] = prepared, access.PublisherIdentity, assignment.GrantID
	}
	setPublic := func(name string, public bool) {
		service := r.Configuration.Services[name]
		service.Public = new(public)
		r.Configuration.Services[name] = service
	}
	r.ExpectedRevision = applied.Revision
	setPublic("api", false)
	disabled, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range disabled.Services {
		if service.Public || service.ServiceID != byName[service.Service].ServiceID || service.Port != byName[service.Service].Port || service.TrustRevision != byName[service.Service].TrustRevision {
			t.Fatal("disable changed a retained binding or private identity", service)
		}
	}
	// disabling the public API keeps its reservation, so enabling the database
	// still fails atomically. neither publisher nor connector authority is traded.
	r.ExpectedRevision = disabled.Revision
	setPublic("db", true)
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("public database ignored retained capacity", err)
	}
	current, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || current.Revision != disabled.Revision || *current.Configuration.Services["db"].Public {
		t.Fatal("failed enable partially committed", current.Revision, err)
	}
	setPublic("db", false)
	setPublic("api", true)
	// explicit false also overrides the retained default in older configurations.
	r.Configuration.Settings.Public = true
	reenabled, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range reenabled.Services {
		old := byName[service.Service]
		if service.Public != (service.Service == "api") || service.ServiceID != old.ServiceID || service.Port != old.Port || service.TrustRevision != old.TrustRevision {
			t.Fatal("re-enable changed an exact service binding", service)
		}
	}
	assignments, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range assignments.Services {
		if assignment.GrantID != grants[assignment.Service] || assignment.Configuration.Public != nil {
			t.Fatal("exposure replaced a publication grant or lifecycle")
		}
	}
	if len(assignments.Services) != len(runs) {
		t.Fatal("exposure removed a publication assignment")
	}
	for name, run := range runs {
		if _, err := d.StartServiceRun(ctx, run.ServiceID, run.RunID, run.RunNumber, publishers[name], now); err != nil {
			t.Fatal("exposure closed an independently authorized run", name, err)
		}
	}
}
