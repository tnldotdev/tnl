package state

import (
	"reflect"
	"testing"
	"time"
)

func TestIntegrationServiceDefinitionContentIdempotency(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "definition_idempotency")
	project := retainedEnvironmentProject(t, d, now)
	request := CreateServiceDefinitionRequest{
		TeamID: project.TeamID, ProjectKey: project.ProjectKey, SourceFingerprint: project.SourceFingerprint,
		ActorID: project.ActorID, Now: now,
		Definition: ServiceDefinition{Services: map[string]ServiceDefinitionService{
			"database": {Protocol: "postgres"}, "api": {Protocol: "http"},
		}},
	}
	first, err := d.CreateServiceDefinition(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Now = now.Add(time.Minute)
	request.Definition.Services = map[string]ServiceDefinitionService{
		"api": {Protocol: "http"}, "database": {Protocol: "postgres"},
	}
	reused, err := d.CreateServiceDefinition(t.Context(), request)
	if err != nil || !reflect.DeepEqual(reused, first) {
		t.Fatal("identical normalized content did not reuse its immutable revision", reused, first, err)
	}
	request.Definition.Services["database"] = ServiceDefinitionService{Protocol: "mysql"}
	second, err := d.CreateServiceDefinition(t.Context(), request)
	if err != nil || second.Revision != first.Revision+1 || second.ConfigurationHash == first.ConfigurationHash {
		t.Fatal("different service shape did not receive a new revision", second, err)
	}
	request.Definition.Services["database"] = ServiceDefinitionService{Protocol: "postgres"}
	request.Now = now.Add(2 * time.Minute)
	reused, err = d.CreateServiceDefinition(t.Context(), request)
	if err != nil || !reflect.DeepEqual(reused, first) {
		t.Fatal("republishing an older shape allocated another revision", reused, err)
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_definitions WHERE team_id=$1 AND project_key=$2`, project.TeamID, project.ProjectKey).Scan(&count); err != nil || count != 2 {
		t.Fatal("content retries inserted extra definition records", count, err)
	}
}
