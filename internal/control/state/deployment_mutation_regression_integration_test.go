package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationDeploymentTargetUpdateAuditRevisions(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_target_audit")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	team, err := d.CreateTeam(ctx, authorityTeamRequest(r.ActorID), now)
	if err != nil {
		t.Fatal(err)
	}
	r.TeamID = team.ID
	admin := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "audit-admin", "admin")
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db": {Protocol: "postgres", Target: "first.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	current, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	service := current.Services["db"].ID
	initial, err := d.ListServiceAudit(ctx, r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: service, Limit: 256}, now)
	if err != nil || len(initial.Events) == 0 {
		t.Fatal("initial deployment audit is missing", initial, err)
	}
	after := initial.Events[len(initial.Events)-1].Cursor
	var expected []serviceaudit.Event
	for index, target := range []string{"second.internal:5432", "first.internal:5432", "second.internal:5432"} {
		actor := r.ActorID
		if index == 2 {
			actor = admin.IdentityID
		}
		at := now.Add(time.Duration(index+1) * time.Second)
		update := UpdateDeploymentRequest{
			DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: actor},
			Selector:        current.ID, ExpectedRevision: current.Revision, Now: at,
			Targets: map[string]DeploymentTarget{"db": {Address: target}},
		}
		next, err := d.UpdateDeployment(ctx, update)
		if err != nil || next.Revision != current.Revision+1 || next.Services["db"].ID != service {
			t.Fatal("target mutation did not advance the existing deployment", next, err)
		}
		expected = append(expected, serviceaudit.Event{
			ActorIdentityID: actor, OccurredAt: at, ConfigurationRevision: next.Revision,
		})
		if _, err := d.UpdateDeployment(ctx, update); !errors.Is(err, ErrDeploymentStale) {
			t.Fatal("a repeated conditional mutation did not stay stale", err)
		}
		update.ExpectedRevision = next.Revision
		update.Now = at.Add(time.Minute)
		unchanged, err := d.UpdateDeployment(ctx, update)
		if err != nil || unchanged.Revision != next.Revision {
			t.Fatal("a no-op target update advanced the deployment", unchanged, err)
		}
		current = next
	}
	page, err := d.ListServiceAudit(ctx, r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: service, After: after, Limit: 256}, now)
	if err != nil {
		t.Fatal(err)
	}
	var updates []serviceaudit.Event
	seen := map[string]bool{}
	for _, event := range page.Events {
		if event.EventType != "deployment.update" {
			continue
		}
		if seen[event.ID] {
			t.Fatal("distinct target mutations share an audit ID", event.ID)
		}
		seen[event.ID] = true
		updates = append(updates, event)
	}
	if len(updates) != len(expected) {
		t.Fatalf("target mutations, retries and no-ops produced %d audit events; want %d", len(updates), len(expected))
	}
	for index, event := range updates {
		want := expected[index]
		if event.ActorIdentityID != want.ActorIdentityID || !event.OccurredAt.Equal(want.OccurredAt) || event.ConfigurationRevision != want.ConfigurationRevision {
			t.Fatalf("target update %d lost its exact mutation facts: %+v, want %+v", index, event, want)
		}
	}
}

func TestIntegrationDeploymentRetainedDeclarationLifecycle(t *testing.T) {
	for _, origin := range []string{"apply", "runtime", "local"} {
		for _, mutation := range []string{"remove", "protocol"} {
			t.Run(origin+"/"+mutation, func(t *testing.T) {
				d, now := newControlStateIntegrationDatabase(t, "deployment_retained_declaration")
				ctx := t.Context()
				r := appliedProjectRequest(t, d, now)
				r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
					"db": {Protocol: "postgres", Target: "database.internal:5432"},
				}}
				selection := "production"
				if origin != "apply" {
					selection = "local"
				}
				r = selectedProjectRequest(r, selection)
				if origin == "runtime" {
					r.Configuration.Services = map[string]ProjectServiceConfiguration{}
				}
				initial, err := d.ApplyProjectConfiguration(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
				var retained Deployment
				switch origin {
				case "apply":
					retained, err = d.GetDeployment(ctx, scope, selection)
				case "runtime":
					retained, err = d.CreateDeployment(ctx, CreateDeploymentRequest{
						DeploymentScope: scope, Name: "customer", IdempotencyKey: "customer", Now: now,
						Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}},
					})
				}
				if err != nil {
					t.Fatal(err)
				}
				r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{}}
				nextSelection := "local"
				if origin == "local" {
					nextSelection = "staging"
				}
				r = selectedProjectRequest(r, nextSelection)
				if mutation == "protocol" {
					r.ServiceDeclarations["db"] = "mysql"
				}
				r.ExpectedRevision = initial.Revision
				if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectManaged) {
					t.Fatal("a retained binding did not protect its logical declaration", err)
				}
				unchanged, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, selection)
				if err != nil || unchanged.Revision != initial.Revision {
					t.Fatal("a rejected declaration mutation changed the project", unchanged, err)
				}
				declarations, err := controlstatedb.New(d.pool).ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
				if err != nil || len(declarations) != 1 || declarations[0].Name != "db" || declarations[0].Protocol != "postgres" {
					t.Fatal("a rejected declaration mutation changed its saved protocol", declarations, err)
				}
				if origin == "local" {
					// the local selection may replace its own retained declaration.
					r = selectedProjectRequest(r, "local")
					if mutation == "protocol" {
						r.ServiceDeclarations["db"] = "mysql"
					}
				} else if err := d.DeleteDeployment(ctx, scope, retained.ID, retained.Revision, now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				changed, err := d.ApplyProjectConfiguration(ctx, r)
				if err != nil || changed.Revision != initial.Revision+1 {
					t.Fatal("a removed binding still protected its historical declaration", changed, err)
				}
				declarations, err = controlstatedb.New(d.pool).ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "remove" && len(declarations) != 0 || mutation == "protocol" && (len(declarations) != 1 || declarations[0].Name != "db" || declarations[0].Protocol != "mysql") {
					t.Fatal("the unbound declaration did not follow the selected input", declarations)
				}
				deployments, err := d.ListDeployments(ctx, scope, "", 100)
				if err != nil || len(deployments) != 0 {
					t.Fatal("declaration reconciliation resurrected a deployment", deployments, err)
				}
				if origin != "local" {
					if _, err := d.GetDeployment(ctx, scope, retained.ID); !errors.Is(err, ErrDeploymentNotFound) {
						t.Fatal("declaration reconciliation restored deleted deployment authority", err)
					}
				}
				if origin == "apply" {
					history, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, selection)
					if err != nil || history.Configuration.Services["db"].Protocol != "postgres" || history.Configuration.Services["db"].Target != "database.internal:5432" || len(history.Services) != 0 {
						t.Fatal("reconciling declarations discarded desired history or restored a retired binding", history, err)
					}
				}
			})
		}
	}
}
