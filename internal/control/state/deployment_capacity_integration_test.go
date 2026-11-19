package state

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationLargeProjectPreservesDeploymentHistory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_capacity_history")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25600}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db": {Protocol: "postgres", Target: "database.internal:5432"},
	}}
	r = selectedProjectRequest(r, "local")
	local, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	r.ExpectedRevision = local.Revision
	saved := make([]Deployment, 0, 32)
	var applied AppliedProjectConfiguration
	for index := range 32 {
		r = selectedProjectRequest(r, fmt.Sprintf("deployment-%02d", index))
		applied, err = d.ApplyProjectConfiguration(ctx, r)
		if err != nil {
			t.Fatal("could not apply deployment", index, err)
		}
		deployment, err := d.GetDeployment(ctx, scope, r.Deployment)
		if err != nil {
			t.Fatal(err)
		}
		saved = append(saved, deployment)
		r.ExpectedRevision = applied.Revision
	}
	assertLiveCount := func(want int) {
		t.Helper()
		deployments, err := d.ListDeployments(ctx, scope, "", 100)
		if err != nil || len(deployments) != want {
			t.Fatal("wrong live deployment count", len(deployments), want, err)
		}
	}
	assertLiveCount(32)
	r.ExpectedRevision--
	replayed, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || !reflect.DeepEqual(replayed, applied) {
		t.Fatal("apply retry changed saved bindings", replayed, err)
	}
	r.ExpectedRevision = applied.Revision
	excess := selectedProjectRequest(r, "excess")
	excess.ExpectedRevision--
	if _, err := d.ApplyProjectConfiguration(ctx, excess); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("apply ignored the stale revision fence", err)
	}
	if err := d.DeleteDeployment(ctx, scope, saved[0].ID, saved[0].Revision, now); err != nil {
		t.Fatal(err)
	}
	assertLiveCount(31)
	r = selectedProjectRequest(r, "fresh-applied")
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("could not apply a new deployment after deleting another", err)
	}
	assertLiveCount(32)
	replayed, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || !reflect.DeepEqual(replayed, applied) {
		t.Fatal("fresh apply retry changed saved state", replayed, err)
	}
	r.ExpectedRevision = applied.Revision
	if err := d.DeleteDeployment(ctx, scope, saved[1].ID, saved[1].Revision, now); err != nil {
		t.Fatal(err)
	}
	request := CreateDeploymentRequest{
		DeploymentScope: scope, Name: "fresh-created", IdempotencyKey: "fresh-created", Now: now,
		Targets: map[string]DeploymentTarget{"db": {Address: "database.internal:5432"}},
	}
	created, err := d.CreateDeployment(ctx, request)
	if err != nil {
		t.Fatal("could not create a new deployment after deleting another", err)
	}
	assertLiveCount(32)
	recovered, err := d.CreateDeployment(ctx, request)
	if err != nil || !reflect.DeepEqual(recovered, created) {
		t.Fatal("management retry changed identity", recovered, err)
	}
	r = selectedProjectRequest(r, request.Name)
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("could not apply an existing management-created deployment", err)
	}
	current, err := d.GetDeployment(ctx, scope, created.ID)
	if err != nil || current.ID != created.ID || current.Services["db"].ID != created.Services["db"].ID {
		t.Fatal("apply replaced the management-created binding", current, err)
	}
	r.ExpectedRevision = applied.Revision
	excess = selectedProjectRequest(r, "excess")
	next, err := d.ApplyProjectConfiguration(ctx, excess)
	if err != nil {
		t.Fatal("could not apply a 33rd live deployment", err)
	}
	excessCreate := request
	excessCreate.Name, excessCreate.IdempotencyKey = "excess-created", "excess-created"
	if _, err := d.CreateDeployment(ctx, excessCreate); err != nil {
		t.Fatal("could not create a 34th live deployment", err)
	}
	assertLiveCount(34)
	if err := d.DeleteDeployment(ctx, scope, current.ID, current.Revision, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateDeployment(ctx, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("deleted creation key replay regained a deployment", err)
	}
	request.IdempotencyKey = "recreate"
	if _, err := d.CreateDeployment(ctx, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("fresh creation key rebound a deleted name", err)
	}
	historical := selectedProjectRequest(r, saved[0].Name)
	if _, err := d.ApplyProjectConfiguration(ctx, historical); err == nil {
		t.Fatal("historical apply resurrected a deleted deployment")
	}
	assertLiveCount(33)
	var owner string
	if err := d.pool.QueryRow(ctx, `SELECT deployment_id FROM control.deployment_names
		WHERE team_id=$1 AND project_key=$2 AND name=$3`, r.TeamID, r.ProjectKey, saved[0].Name).Scan(&owner); err != nil || owner != saved[0].ID {
		t.Fatal("deleted deployment name lost its immutable identity fence", owner, err)
	}
	row, err := controlstatedb.New(d.pool).GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		t.Fatal(err)
	}
	if row.Revision != next.Revision {
		t.Fatal("historical replay changed the project revision", row.Revision, next.Revision)
	}
	record, err := d.openAppliedProjectRecord(row)
	if err != nil || len(record.Deployments) != 36 || !reflect.DeepEqual(record.Deployments["local"], local.Configuration) {
		t.Fatal("larger project discarded desired history or changed local input", len(record.Deployments), err)
	}
	for _, name := range []string{saved[0].Name, saved[1].Name, created.Name} {
		history, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, name)
		if err != nil || !reflect.DeepEqual(history.Configuration, applied.Configuration) || len(history.Services) != 0 {
			t.Fatal("deleted desired history changed or regained bindings", name, history, err)
		}
	}
}

func TestIntegrationApplyWithManyManagementCreatedSiblings(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_capacity_management")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25600}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db": {Protocol: "postgres", Target: "database.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	request := CreateDeploymentRequest{
		DeploymentScope: scope, Now: now,
		Targets: map[string]DeploymentTarget{"db": {Address: "database.internal:5432"}},
	}
	for index := range 31 {
		request.Name = fmt.Sprintf("customer-%02d", index)
		request.IdempotencyKey = request.Name
		if _, err := d.CreateDeployment(ctx, request); err != nil {
			t.Fatal("could not create deployment", index, err)
		}
	}
	r.ExpectedRevision = applied.Revision
	r = selectedProjectRequest(r, "excess")
	next, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("could not apply another deployment with many management-created siblings", err)
	}
	request.Name, request.IdempotencyKey = "excess-created", "excess-created"
	if _, err := d.CreateDeployment(ctx, request); err != nil {
		t.Fatal("could not create another deployment", err)
	}
	deployments, err := d.ListDeployments(ctx, scope, "", 100)
	if err != nil || len(deployments) != 34 {
		t.Fatal("did not retain all deployments", len(deployments), err)
	}
	local := selectedProjectRequest(r, "local")
	local.ExpectedRevision = next.Revision
	if _, err := d.ApplyProjectConfiguration(ctx, local); err != nil {
		t.Fatal("could not apply local input", err)
	}
}
