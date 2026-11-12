package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	ErrCollectionInvalid  = errors.New("collection or default definition is invalid")
	ErrCollectionStale    = errors.New("collection mutation revision changed")
	ErrCollectionNotFound = errors.New("collection or definition revision was not found in this project")
)

func collectionOperationError(err error) error {
	if errors.Is(err, ErrProjectConfigurationInvalid) || errors.Is(err, ErrServiceDefinitionInvalid) {
		return errors.Join(ErrCollectionInvalid, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(ErrCollectionNotFound, err)
	}
	return err
}

// collections own selection and durable membership, not publisher assignments or
// permission reconciliation. these state operations require current team managers.
type Collection struct {
	ID                        string `json:"collection_id"`
	TeamID                    string `json:"team_id"`
	ProjectKey                string `json:"project_key"`
	Name                      string `json:"name"`
	DefaultDefinitionRevision int64  `json:"default_definition_revision"`
	MutationRevision          int64  `json:"mutation_revision"`
}

type CreateCollectionRequest struct {
	TeamID, ProjectKey, ActorID, Name string
	DefaultDefinitionRevision         int64
	Now                               time.Time
}

type UpdateCollectionDefaultRequest struct {
	TeamID, ProjectKey, ActorID, CollectionID string
	ExpectedRevision, DefinitionRevision      int64
	Now                                       time.Time
}

func collectionStatus(row controlstatedb.ControlCollection) Collection {
	return Collection{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Name: row.Name, DefaultDefinitionRevision: row.DefaultDefinitionRevision, MutationRevision: row.MutationRevision}
}

// name reserves the collection identity. a retry matches its original default,
// not its current default, and always repeats current manager authorization.
func (d *Database) CreateCollection(ctx context.Context, r CreateCollectionRequest) (result Collection, retErr error) {
	defer func() { retErr = collectionOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || !validEnvironmentName(r.Name) || r.DefaultDefinitionRevision < 1 {
		return result, ErrCollectionInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create collection", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	row, err := q.GetCollectionByName(ctx, controlstatedb.GetCollectionByNameParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Name: r.Name})
	if err == nil {
		if row.InitialDefaultDefinitionRevision != r.DefaultDefinitionRevision {
			return result, ErrServiceConflict
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		definition, e := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, r.DefaultDefinitionRevision)
		if e != nil {
			return result, e
		}
		if definition.SourceFingerprint != project.SourceFingerprint {
			return result, ErrProjectSourceConflict
		}
		var id string
		id, err = opaqueid.New(opaqueid.CollectionPrefix)
		if err != nil {
			return result, err
		}
		row, err = q.CreateCollection(ctx, controlstatedb.CreateCollectionParams{ID: id, TeamID: r.TeamID, ProjectKey: r.ProjectKey, Name: r.Name, DefaultDefinitionRevision: r.DefaultDefinitionRevision, CreatedByIdentityID: r.ActorID, CreatedAt: timestamptz(r.Now)})
	}
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	return collectionStatus(row), tx.Commit(ctx)
}

func (d *Database) GetCollection(ctx context.Context, team, project, id, actor string) (result Collection, retErr error) {
	return d.inspectCollection(ctx, team, project, id, actor, EnvironmentPublisherManager{})
}

func (d *Database) InspectCollection(ctx context.Context, team, project, id string, manager EnvironmentPublisherManager) (Collection, error) {
	return d.inspectCollection(ctx, team, project, id, "", manager)
}

func (d *Database) inspectCollection(ctx context.Context, team, project, id, actor string, manager EnvironmentPublisherManager) (result Collection, retErr error) {
	defer func() { retErr = collectionOperationError(retErr) }()
	if !naming.ValidProjectKey(project) || !opaqueid.Valid(id, opaqueid.CollectionPrefix) {
		return result, ErrCollectionInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get collection", &retErr)()
	manager, err = environmentManagement(ctx, tx, team, actor, manager)
	if err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).GetCollection(ctx, controlstatedb.GetCollectionParams{TeamID: team, ProjectKey: project, ID: id})
	if err != nil {
		return result, err
	}
	definition, err := loadServiceDefinition(ctx, tx, team, project, row.DefaultDefinitionRevision)
	if err != nil {
		return result, err
	}
	if err = manager.authorize(ctx, tx, ProvisioningScope{Operation: ProvisioningRead, TeamID: team, ProjectKey: project, CollectionID: row.ID, Services: definitionServiceNames(definition.Definition)}, false); err != nil {
		return result, err
	}
	if err = manager.finish(ctx, tx, team); err != nil {
		return result, err
	}
	return collectionStatus(row), tx.Commit(ctx)
}

func (d *Database) ListCollections(ctx context.Context, team, project, actor string) (result []Collection, retErr error) {
	defer func() { retErr = collectionOperationError(retErr) }()
	if !naming.ValidProjectKey(project) {
		return nil, ErrCollectionInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list collections", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, team, actor); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListCollections(ctx, controlstatedb.ListCollectionsParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return nil, err
	}
	result = make([]Collection, 0, len(rows))
	for _, row := range rows {
		result = append(result, collectionStatus(row))
	}
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

// updating a default never reads or reconciles member environments. the lock
// order is team authority, project, collection; creation follows the same order.
func (d *Database) UpdateCollectionDefault(ctx context.Context, r UpdateCollectionDefaultRequest) (result Collection, retErr error) {
	defer func() { retErr = collectionOperationError(retErr) }()
	if !naming.ValidProjectKey(r.ProjectKey) || !opaqueid.Valid(r.CollectionID, opaqueid.CollectionPrefix) || r.ExpectedRevision < 1 || r.ExpectedRevision == 1<<63-1 || r.DefinitionRevision < 1 {
		return result, ErrCollectionInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "update collection default", &retErr)()
	if err = authorizeEnvironmentManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return result, err
	}
	row, err := q.LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.CollectionID})
	if err != nil {
		return result, err
	}
	if row.MutationRevision != r.ExpectedRevision {
		return result, ErrCollectionStale
	}
	definition, err := loadServiceDefinition(ctx, tx, r.TeamID, r.ProjectKey, r.DefinitionRevision)
	if err != nil {
		return result, err
	}
	if definition.SourceFingerprint != project.SourceFingerprint {
		return result, ErrProjectSourceConflict
	}
	row, err = q.UpdateCollectionDefault(ctx, controlstatedb.UpdateCollectionDefaultParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.CollectionID, DefaultDefinitionRevision: r.DefinitionRevision, UpdatedAt: timestamptz(r.Now), MutationRevision: r.ExpectedRevision})
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	return collectionStatus(row), tx.Commit(ctx)
}
