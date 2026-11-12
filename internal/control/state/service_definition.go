package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// definitions describe shape, never targets, visitor policy or authority.
var ErrServiceDefinitionInvalid = errors.New("service definition is invalid")

type ServiceDefinitionService struct {
	Protocol string `json:"protocol"`
}

type ServiceDefinition struct {
	Services map[string]ServiceDefinitionService `json:"services"`
}

type ServiceDefinitionRevision struct {
	TeamID            string            `json:"team_id"`
	ProjectKey        string            `json:"project_key"`
	Revision          int64             `json:"revision"`
	SourceFingerprint string            `json:"source_fingerprint"`
	ConfigurationHash string            `json:"configuration_hash"`
	Definition        ServiceDefinition `json:"definition"`
	CreatedAt         time.Time         `json:"created_at"`
}

type CreateServiceDefinitionRequest struct {
	TeamID, ProjectKey, SourceFingerprint, ProjectLabel, ActorID string
	Definition                                                   ServiceDefinition
	Now                                                          time.Time
}

func NormalizeServiceDefinition(input ServiceDefinition) (ServiceDefinition, string, error) {
	if len(input.Services) == 0 || len(input.Services) > 128 {
		return ServiceDefinition{}, "", ErrServiceDefinitionInvalid
	}
	result := ServiceDefinition{Services: make(map[string]ServiceDefinitionService, len(input.Services))}
	for name, service := range input.Services {
		if !serviceName.MatchString(name) || service.Protocol == "" || (ServiceMetadata{Protocol: service.Protocol}).Validate() != nil {
			return ServiceDefinition{}, "", ErrServiceDefinitionInvalid
		}
		result.Services[name] = service
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > 32<<10 {
		return ServiceDefinition{}, "", ErrServiceDefinitionInvalid
	}
	hash := sha256.Sum256(data)
	return result, hex.EncodeToString(hash[:]), nil
}

// the project row supplies immutable provenance and the resource FK root. it has
// no project-wide desired configuration, mutation revision or encrypted targets.
func (d *Database) ensureDefinitionProject(ctx context.Context, tx pgx.Tx, team, project, source, label, actor string, now time.Time) (controlstatedb.ControlAppliedProject, error) {
	q := controlstatedb.New(tx)
	if err := checkLocalProjectSource(ctx, tx, team, project, source); err != nil {
		return controlstatedb.ControlAppliedProject{}, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	if errors.Is(err, pgx.ErrNoRows) {
		if label == "" {
			label = project
		}
		if !validProjectDNSLabel(label) {
			return row, ErrProjectConfigurationInvalid
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.applied_projects(team_id,project_key,source_fingerprint,project_label,created_by_identity_id,updated_at) VALUES($1,$2,$3,$4,$5,$6)`, team, project, source, label, actor, now)
		if err != nil {
			return row, err
		}
		row, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	}
	if err == nil && row.SourceFingerprint != source {
		return row, ErrProjectSourceConflict
	}
	if err == nil && label != "" && label != row.ProjectLabel {
		return row, ErrProjectSourceConflict
	}
	return row, err
}

func (d *Database) CreateServiceDefinition(ctx context.Context, r CreateServiceDefinitionRequest) (result ServiceDefinitionRevision, retErr error) {
	defer func() {
		if errors.Is(retErr, ErrProjectConfigurationInvalid) {
			retErr = errors.Join(ErrServiceDefinitionInvalid, retErr)
		}
	}()
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) {
		return result, ErrServiceDefinitionInvalid
	}
	definition, hash, err := NormalizeServiceDefinition(r.Definition)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create service definition", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	if _, err = d.ensureDefinitionProject(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.ProjectLabel, r.ActorID, r.Now); err != nil {
		return result, err
	}
	result, err = scanServiceDefinition(tx.QueryRow(ctx, `SELECT team_id,project_key,revision,source_fingerprint,configuration_hash,definition,created_at
		FROM control.service_definitions WHERE team_id=$1 AND project_key=$2 AND configuration_hash=$3`, r.TeamID, r.ProjectKey, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		data, _ := json.Marshal(definition)
		result, err = scanServiceDefinition(tx.QueryRow(ctx, `INSERT INTO control.service_definitions(team_id,project_key,revision,source_fingerprint,configuration_hash,definition,created_by_identity_id,created_at)
			SELECT $1,$2,COALESCE(max(revision),0)+1,$3,$4,$5::jsonb,$6,$7 FROM control.service_definitions WHERE team_id=$1 AND project_key=$2
			RETURNING team_id,project_key,revision,source_fingerprint,configuration_hash,definition,created_at`, r.TeamID, r.ProjectKey, r.SourceFingerprint, hash, string(data), r.ActorID, r.Now))
	}
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return ServiceDefinitionRevision{}, err
	}
	return result, tx.Commit(ctx)
}

func scanServiceDefinition(row pgx.Row) (r ServiceDefinitionRevision, err error) {
	var data []byte
	err = row.Scan(&r.TeamID, &r.ProjectKey, &r.Revision, &r.SourceFingerprint, &r.ConfigurationHash, &data, &r.CreatedAt)
	if err != nil {
		return r, err
	}
	r.Definition, err = decodeServiceDefinition(data, r.ConfigurationHash)
	return r, err
}

func decodeServiceDefinition(data []byte, expectedHash string) (ServiceDefinition, error) {
	var definition ServiceDefinition
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definition); err != nil {
		return ServiceDefinition{}, errors.Join(ErrServiceDefinitionInvalid, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ServiceDefinition{}, ErrServiceDefinitionInvalid
	}
	definition, hash, err := NormalizeServiceDefinition(definition)
	if err != nil || hash != expectedHash {
		return ServiceDefinition{}, ErrServiceDefinitionInvalid
	}
	return definition, nil
}

func loadServiceDefinition(ctx context.Context, tx pgx.Tx, team, project string, revision int64) (ServiceDefinitionRevision, error) {
	return scanServiceDefinition(tx.QueryRow(ctx, `SELECT team_id,project_key,revision,source_fingerprint,configuration_hash,definition,created_at FROM control.service_definitions WHERE team_id=$1 AND project_key=$2 AND revision=$3`, team, project, revision))
}
