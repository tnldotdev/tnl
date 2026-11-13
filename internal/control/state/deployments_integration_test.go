package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentCRUDSharesSavedBindingsWithApply(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_crud")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{
		PublisherGroups: map[string]ProjectPublisherGroup{"production": {}},
		Services: map[string]ProjectServiceConfiguration{"db": {
			PublisherGroup: "production", Protocol: "postgres", Target: "production.internal:5432",
			Access: &ProjectServiceAccess{Team: true},
		}},
	}
	r = selectedProjectRequest(r, "production")
	project, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	request := CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "customer-setup-1", Now: now,
		Targets: map[string]DeploymentTarget{"db": {Address: "orders.abc123.us-east-1.rds.amazonaws.com:5432", TLS: &DeploymentTargetTLS{CA: "aws-rds"}}}}
	customer, err := d.CreateDeployment(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if customer.Revision != 1 || customer.Services["db"].ID == project.Services[0].ServiceID || customer.Services["db"].Protocol != "postgres" || customer.Targets["db"].TLS == nil || customer.Targets["db"].TLS.Hostname != "orders.abc123.us-east-1.rds.amazonaws.com" {
		t.Fatal("deployment did not create independent saved services and trust", customer)
	}
	legacy, err := d.GetProjectService(ctx, GetProjectServiceRequest{Deployment: "production", TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", IdentityID: r.ActorID, Now: now})
	if err != nil || legacy.ID != project.Services[0].ServiceID {
		t.Fatal("legacy name lookup selected a customer binding", err)
	}
	recovered, err := d.CreateDeployment(ctx, request)
	if err != nil || !reflect.DeepEqual(recovered, customer) {
		t.Fatal("lost creation reply did not recover the original deployment", err)
	}
	otherIntent := request
	otherIntent.Name = "another"
	if _, err = d.CreateDeployment(ctx, otherIntent); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("request key accepted a different intent", err)
	}
	listed, err := d.ListDeployments(ctx, scope, "", 100)
	if err != nil || len(listed) != 2 {
		t.Fatal("deployment list did not include both saved records", listed, err)
	}
	page, err := d.ListDeployments(ctx, scope, listed[0].ID, 1)
	if err != nil || len(page) != 1 || page[0].ID != listed[1].ID {
		t.Fatal("deployment cursor lost or repeated a record", page, err)
	}
	selected, err := d.GetDeployment(ctx, scope, customer.ID)
	if err != nil || !reflect.DeepEqual(selected, customer) {
		t.Fatal("ID selection did not read the same deployment", err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "customer", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	if len(replica.assignments.Services) != 1 || replica.assignments.Services[0].ServiceID != customer.Services["db"].ID {
		t.Fatal("publisher enrolled for another deployment's binding", replica.assignments)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now); err != nil {
		t.Fatal(err)
	}
	update := UpdateDeploymentRequest{DeploymentScope: scope, Selector: "production", ExpectedRevision: 1, Now: now,
		Targets: map[string]DeploymentTarget{"db": {Address: "changed-production.internal:5432"}}}
	production, err := d.UpdateDeployment(ctx, update)
	if err != nil || production.Revision != 2 || production.Services["db"].ID != project.Services[0].ServiceID {
		t.Fatal("update replaced rather than changed the saved binding", production, err)
	}
	if _, err = d.UpdateDeployment(ctx, update); !errors.Is(err, ErrDeploymentStale) {
		t.Fatal("conditional update accepted a stale revision", err)
	}
	var visitorGrant bool
	if err = d.pool.QueryRow(ctx, `SELECT visitor.revoked_at IS NULL FROM control.applied_project_services binding
		JOIN control.visitor_grants visitor ON visitor.id=binding.visitor_grant_id WHERE binding.service_id=$1`, production.Services["db"].ID).Scan(&visitorGrant); err != nil || !visitorGrant {
		t.Fatal("target-only update changed visitor policy", err)
	}
	// the apply document has not changed, but the serving target has. apply
	// must compare against the same saved deployment, not skip by project hash.
	r.ExpectedRevision = project.Revision
	project, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	production, err = d.GetDeployment(ctx, scope, "production")
	if err != nil || production.Targets["db"].Address != "production.internal:5432" || production.Revision != 3 {
		t.Fatal("manager apply did not restore its selected saved target", production, err)
	}
	assignments, err := d.GetPublisherGroupAssignments(ctx, replica.lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(assignments, replica.assignments) {
		t.Fatal("manager apply swept a same-named customer binding", err)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now); err != nil {
		t.Fatal("manager apply invalidated customer acknowledgement", err)
	}
	// declarations used by another deployment cannot silently change protocol.
	r.ExpectedRevision = project.Revision
	db := r.Configuration.Services["db"]
	db.Protocol = "mysql"
	r.Configuration.Services["db"] = db
	r.ServiceDeclarations["db"] = "mysql"
	if _, err = d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("apply changed a sibling deployment's protocol", err)
	}
	r.ServiceDeclarations["db"] = "postgres"
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}}
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal("removing apply-owned services touched a customer declaration", err)
	}
	declarations, err := controlstatedb.New(d.pool).ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil || len(declarations) != 1 || declarations[0].Name != "db" || declarations[0].Protocol != "postgres" {
		t.Fatal("apply removed a declaration retained by a customer deployment", declarations, err)
	}
	selected, err = d.GetDeployment(ctx, scope, "customer")
	if err != nil || !reflect.DeepEqual(selected, customer) {
		t.Fatal("apply removal changed the customer deployment", err)
	}
	var ciphertext []byte
	if err = d.pool.QueryRow(ctx, `SELECT configuration_ciphertext FROM control.project_publisher_groups WHERE id=$1`, customer.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("orders.abc123")) {
		t.Fatal("customer targets were not encrypted", err)
	}
	wire, err := json.Marshal(customer)
	if err != nil || bytes.Contains(wire, []byte("configuration_hash")) || bytes.Contains(wire, []byte("grant_id")) || bytes.Contains(wire, []byte("enrollment")) {
		t.Fatal("deployment read exposed internal recovery or publisher credentials", err)
	}
	if err = d.DeleteDeployment(ctx, scope, customer.ID, customer.Revision+1, now); !errors.Is(err, ErrDeploymentStale) {
		t.Fatal("delete ignored its conditional revision", err)
	}
	if err = d.DeleteDeployment(ctx, scope, customer.ID, customer.Revision, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetPublisherGroupAssignments(ctx, replica.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("deleted deployment retained a live publisher", err)
	}
	if _, err = d.GetDeployment(ctx, scope, customer.ID); !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatal("deleted deployment remained readable", err)
	}
	if _, err = d.CreateDeployment(ctx, request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("retry recreated a deleted deployment", err)
	}
}

func TestIntegrationDeploymentSavedConfigurationConsumers(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_consumers")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	cluster := "orders"
	r.Configuration = ProjectConfiguration{
		PublisherGroups: map[string]ProjectPublisherGroup{"production": {}},
		Services: map[string]ProjectServiceConfiguration{
			"web":  {PublisherGroup: "production", Target: "localhost:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}}},
			"kube": {PublisherGroup: "production", Protocol: "kubernetes", TargetDiscovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: &cluster}},
		},
	}
	r = selectedProjectRequest(r, "production")
	project, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(ctx, scope, "production")
	if err != nil || production.Targets["kube"].Discovery == nil || production.Targets["kube"].Address != "" {
		t.Fatal("read lost publisher-side discovery", production, err)
	}
	customer, err := d.CreateDeployment(ctx, CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "customer", Now: now,
		Targets: map[string]DeploymentTarget{"web": {Address: "customer.internal:3000"}}})
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	settings, err := d.serviceHTTPSettings(ctx, q, customer.Services["web"].ID)
	if err != nil || settings != nil {
		t.Fatal("customer inherited production HTTP policy", settings, err)
	}
	settings, err = d.serviceHTTPSettings(ctx, q, production.Services["web"].ID)
	if err != nil || settings == nil || settings.Access == nil || !reflect.DeepEqual(settings.Access.IP, []string{"192.0.2.0/24"}) {
		t.Fatal("production lost its own HTTP restriction", settings, err)
	}
	approved, err := d.visitorKubernetesAuth(ctx, q, production.Services["kube"].ID)
	if err != nil || approved == nil || approved.Cluster != cluster {
		t.Fatal("visitor lost current EKS facts", approved, err)
	}
	_, err = d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: production.ID, ExpectedRevision: production.Revision, Now: now,
		Targets: map[string]DeploymentTarget{"kube": {Address: "new-kube.internal:6443"}}})
	if err != nil {
		t.Fatal(err)
	}
	approved, err = d.visitorKubernetesAuth(ctx, q, production.Services["kube"].ID)
	if err != nil || approved != nil {
		t.Fatal("visitor retained replaced EKS discovery metadata", approved, err)
	}
	renamed, err := d.RenamePublisherGroup(ctx, r.TeamID, r.ProjectKey, "customer", "tenant", r.ActorID, project.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.GetDeployment(ctx, scope, customer.ID)
	if err != nil || current.Name != "tenant" || !reflect.DeepEqual(current.Targets, customer.Targets) || current.Services["web"].ID != customer.Services["web"].ID {
		t.Fatal("selector rename replaced customer targets or identities", current, err)
	}
	_, err = d.RenamePublisherNamespace(ctx, RenamePublisherNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Group: "tenant", NamespaceLabel: "private", ActorID: r.ActorID, IdempotencyKey: "namespace-customer", ExpectedRevision: renamed.Revision, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	current, err = d.GetDeployment(ctx, scope, customer.ID)
	if err != nil || !reflect.DeepEqual(current.Targets, customer.Targets) || current.Services["web"].Endpoint.Hostname == customer.Services["web"].Endpoint.Hostname {
		t.Fatal("namespace change overwrote targets or kept old endpoint authority", current, err)
	}
}

func TestIntegrationDeploymentLockWaitRechecksCurrentManager(t *testing.T) {
	for _, operation := range []string{"read", "recover", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "deployment_lock_"+operation)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			r := appliedProjectRequest(t, d, now)
			r = selectedProjectRequest(r, "local")
			if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
				t.Fatal(err)
			}
			scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
			request := CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "setup", Now: now,
				Targets: map[string]DeploymentTarget{"web": {Address: "localhost:3000"}}}
			created, err := d.CreateDeployment(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockProjectPublisherGroup(ctx, created.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			result := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "read":
					_, err = d.GetDeployment(ctx, scope, created.ID)
				case "recover":
					_, err = d.CreateDeployment(ctx, request)
				case "update":
					_, err = d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: created.ID, ExpectedRevision: 1, Now: now, Targets: map[string]DeploymentTarget{"web": {Address: "localhost:4000"}}})
				case "delete":
					err = d.DeleteDeployment(ctx, scope, created.ID, 1, now)
				}
				result <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), result)
			// disable after the first authority check, while the operation waits
			// for the saved deployment. no request clock can restore this actor.
			if _, err = gate.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, scope.ActorID, now); err != nil {
				t.Fatal(err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, result); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("operation escaped revocation during a lock wait", err)
			}
			var target string
			row, err := controlstatedb.New(d.pool).LockProjectPublisherGroup(ctx, created.ID)
			if err != nil {
				t.Fatal("denied deletion committed", err)
			}
			configuration, err := d.openDeploymentConfiguration(row)
			if err == nil {
				target = configuration.Services["web"].Target
			}
			if err != nil || target != "localhost:3000" || row.Revision != 1 {
				t.Fatal("denied update committed", target, err)
			}
		})
	}
}

func TestIntegrationDeploymentReadsAndRecoveryRequireCurrentManager(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_current_manager")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r = selectedProjectRequest(r, "local")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	request := CreateDeploymentRequest{DeploymentScope: scope, Name: "customer", IdempotencyKey: "setup", Now: now,
		Targets: map[string]DeploymentTarget{"web": {Address: "http://localhost:3000"}}}
	created, err := d.CreateDeployment(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	foreign := scope
	foreign.ProjectKey = "another"
	if _, err = d.GetDeployment(ctx, foreign, created.ID); !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatal("project selector crossed the ownership boundary", err)
	}
	foreign.TeamID = "tm_" + "0000000000000000000000"
	if _, err = d.GetDeployment(ctx, foreign, created.ID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("foreign team read leaked a deployment", err)
	}
	if _, err = d.pool.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	checks := map[string]func() error{
		"get":     func() error { _, err := d.GetDeployment(ctx, scope, created.ID); return err },
		"list":    func() error { _, err := d.ListDeployments(ctx, scope, "", 100); return err },
		"recover": func() error { _, err := d.CreateDeployment(ctx, request); return err },
		"update": func() error {
			_, err := d.UpdateDeployment(ctx, UpdateDeploymentRequest{DeploymentScope: scope, Selector: created.ID, ExpectedRevision: 1, Targets: request.Targets, Now: now})
			return err
		},
		"delete": func() error { return d.DeleteDeployment(ctx, scope, created.ID, 1, now) },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("revoked manager retained access", err)
			}
		})
	}
}
