package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentConfigurationRevisionIsIsolated(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_configuration_revision")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{
		Settings: &DeploymentSettings{},
		Services: map[string]ProjectServiceConfiguration{
			"database": {Protocol: "postgres", Target: "production.internal:5432"},
			"stage":    {Protocol: "postgres", Target: "staging.internal:5432"},
		},
	}
	production := projectServiceSelection(r, "production", "database")
	first, err := d.ApplyProjectConfiguration(ctx, production)
	if err != nil {
		t.Fatal(err)
	}
	r = projectServiceSelection(r, "staging", "stage")
	r.ExpectedRevision = first.Revision
	project, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := controlstatedb.New(d.pool).ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil || len(declarations) != 2 || declarations[0].Name != "database" || declarations[0].Protocol != "postgres" || declarations[1].Name != "stage" || declarations[1].Protocol != "postgres" {
		t.Fatal("logical declarations lost service names or protocols", declarations, err)
	}
	replicas := map[string]enrolledGroupReplica{}
	for _, name := range []string{"production", "staging"} {
		enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, name, r.ActorID, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		replica := enrollAppliedGroup(t, d, r, enrollment, now)
		replicas[name] = replica
		if err = d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now); err != nil {
			t.Fatal(err)
		}
	}
	r.ExpectedRevision = project.Revision
	stage := r.Configuration.Services["stage"]
	stage.Target = "new-staging.internal:5432"
	r.Configuration.Services["stage"] = stage
	project, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"production", "staging"} {
		replica := replicas[name]
		current, err := d.GetPublisherGroupAssignments(ctx, replica.lease.AccessToken, now)
		if err != nil {
			t.Fatal(err)
		}
		if name == "production" {
			if !reflect.DeepEqual(current, replica.assignments) {
				t.Fatal("staging update changed production assignments or acknowledgement facts", current)
			}
			if err = d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now); err != nil {
				t.Fatal("staging invalidated production acknowledgement", err)
			}
		} else {
			if current.Revision != replica.assignments.Revision+1 || current.ConfigurationHash == replica.assignments.ConfigurationHash || len(current.Services) != 1 || current.Services[0].Configuration.Target != stage.Target {
				t.Fatal("staging retained old targets or configuration facts", current)
			}
			if err = d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now); !errors.Is(err, ErrProjectConfigurationStale) {
				t.Fatal("staging accepted an old acknowledgement", err)
			}
		}
		var ciphertext []byte
		if err = d.pool.QueryRow(ctx, `SELECT configuration_ciphertext FROM control.project_publisher_groups WHERE id=$1`, replica.member.GroupID).Scan(&ciphertext); err != nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte("internal:5432")) {
			t.Fatal("deployment targets were not encrypted", err)
		}
		for _, service := range project.Services {
			if service.PublisherGroup == name && service.DesiredRevision != current.Revision {
				t.Fatal("service used another deployment's revision", service)
			}
		}
	}
}

func TestIntegrationDeploymentConfigurationRejectsInvalidShape(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_configuration_shape")
	r := appliedProjectRequest(t, d, now)
	r.Configuration.Services = map[string]ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: "database.internal:5432"}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	row, err := controlstatedb.New(d.pool).LockProjectPublisherGroup(t.Context(), applied.Groups[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"retired settings": []byte(`{"publisher_groups":{"production":{}},"services":{}}`),
		"retired binding":  []byte(`{"namespace":"` + row.Namespace + `","settings":{},"services":{"db":{"publisher_group":"production","protocol":"postgres","target":"database.internal:5432"}}}`),
		"trailing value":   []byte(`{"namespace":"` + row.Namespace + `","settings":{},"services":{}} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			if name != "trailing value" && !json.Valid(data) {
				t.Fatal("invalid fixture JSON")
			}
			row.ConfigurationCiphertext, err = d.storageKey.Seal(deploymentConfigurationContext(row.ID), data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.openDeploymentConfiguration(row); err == nil {
				t.Fatal("stored configuration accepted an invalid shape")
			}
		})
	}
}
