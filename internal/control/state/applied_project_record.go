package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// desired selections are independent. each serving deployment snapshot remains
// authoritative; runtime target updates do not rewrite this apply input.
type appliedProjectRecord struct {
	ServiceDeclarations map[string]string               `json:"service_declarations"`
	Deployments         map[string]ProjectConfiguration `json:"deployments"`
}

func (d *Database) openAppliedProjectRecord(row controlstatedb.ControlAppliedProject) (appliedProjectRecord, error) {
	var record appliedProjectRecord
	data, _, err := d.storageKey.Open(row.StorageKeyID, appliedProjectContext(row.TeamID, row.ProjectKey), row.ConfigurationCiphertext)
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode applied project: %w", err)
	}
	if record.Deployments == nil {
		record.Deployments = map[string]ProjectConfiguration{}
	}
	if record.ServiceDeclarations == nil {
		record.ServiceDeclarations = map[string]string{}
	}
	return record, nil
}

// desired history does not reserve workload names or authorize executions after
// its deployment is deleted. callers hold the project row while reading this
// active registry, including during apply's transactional reconciliation.
func (record appliedProjectRecord) workloads(ctx context.Context, q *controlstatedb.Queries, project controlstatedb.ControlAppliedProject) (map[string]ProjectWorkload, error) {
	deployments, err := q.ListProjectPublisherGroups(ctx, controlstatedb.ListProjectPublisherGroupsParams{TeamID: project.TeamID, ProjectKey: project.ProjectKey})
	if err != nil {
		return nil, err
	}
	policies := map[string]ProjectWorkload{}
	for _, deployment := range deployments {
		selected := record.Deployments[deployment.Name]
		for name, policy := range selected.Workloads {
			if _, exists := policies[name]; exists || policy.Deployment != deployment.Name {
				return nil, ErrProjectConfigurationInvalid
			}
			policies[name] = policy
		}
	}
	return policies, nil
}

func (d *Database) openAppliedProject(row controlstatedb.ControlAppliedProject, deployment string) (ProjectConfiguration, error) {
	record, err := d.openAppliedProjectRecord(row)
	if err != nil {
		return ProjectConfiguration{}, err
	}
	configuration, found := record.Deployments[deployment]
	if !found {
		return ProjectConfiguration{}, pgx.ErrNoRows
	}
	return configuration, nil
}
