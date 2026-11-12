package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// a publisher carries the exact assigned application, separately from target
// TLS/protocol metadata. rollback can restore a hash, never an old revision.
type EnvironmentPublication struct {
	EnvironmentID     string `json:"environment_id"`
	MutationRevision  int64  `json:"mutation_revision"`
	ConfigurationHash string `json:"configuration_hash"`
}

func (p EnvironmentPublication) valid() bool {
	return opaqueid.Valid(p.EnvironmentID, opaqueid.EnvironmentPrefix) && p.MutationRevision > 0 && fingerprintPattern.MatchString(p.ConfigurationHash)
}

func sameEnvironmentPublication(a, b *EnvironmentPublication) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func environmentPublication(row controlstatedb.ControlEnvironment) EnvironmentPublication {
	return EnvironmentPublication{EnvironmentID: row.ID, MutationRevision: row.MutationRevision, ConfigurationHash: row.ConfigurationHash}
}

// every remote assignment group has one environment owner. readers reject an
// incomplete association within a transaction before deferred FKs run.
func publisherGroupEnvironment(ctx context.Context, q *controlstatedb.Queries, group string) (controlstatedb.ControlEnvironment, bool, error) {
	ownership, err := q.PublisherGroupEnvironmentOwnership(ctx, group)
	if err != nil {
		return controlstatedb.ControlEnvironment{}, false, err
	}
	if !ownership.ForwardEnvironmentID.Valid && !ownership.ReverseEnvironmentID.Valid {
		return controlstatedb.ControlEnvironment{}, false, ErrEnvironmentInvalid
	}
	if !ownership.ForwardEnvironmentID.Valid || !ownership.ReverseEnvironmentID.Valid || ownership.ForwardEnvironmentID.String != ownership.ReverseEnvironmentID.String {
		return controlstatedb.ControlEnvironment{}, true, ErrEnvironmentInvalid
	}
	row, err := q.GetEnvironmentForGroup(ctx, group)
	return row, true, err
}

// service admission holds the team share lock and service parent. environment
// apply requires the conflicting team mutation lock before any environment or
// resource write. read current facts here without reversing that lock order.
func validateEnvironmentPublication(ctx context.Context, q *controlstatedb.Queries, service string, requested *EnvironmentPublication) error {
	group, err := q.ServicePublisherGroup(ctx, text(service))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) || !group.Valid {
		if requested != nil {
			return ErrEnvironmentStale
		}
		return nil
	}
	row, mapped, err := publisherGroupEnvironment(ctx, q, group.String)
	if err != nil {
		return err
	}
	if !mapped {
		return ErrEnvironmentStale
	}
	if row.RetiredAt.Valid || requested == nil || !requested.valid() || *requested != environmentPublication(row) {
		return ErrEnvironmentStale
	}
	return nil
}

func preparedEnvironmentPublication(run controlstatedb.ControlServiceRun) (*EnvironmentPublication, error) {
	if !run.EnvironmentID.Valid && !run.EnvironmentMutationRevision.Valid && !run.EnvironmentConfigurationHash.Valid {
		return nil, nil
	}
	if !run.EnvironmentID.Valid || !run.EnvironmentMutationRevision.Valid || !run.EnvironmentConfigurationHash.Valid {
		return nil, ErrEnvironmentStale
	}
	publication := &EnvironmentPublication{EnvironmentID: run.EnvironmentID.String, MutationRevision: run.EnvironmentMutationRevision.Int64, ConfigurationHash: run.EnvironmentConfigurationHash.String}
	if !publication.valid() {
		return nil, ErrEnvironmentStale
	}
	return publication, nil
}

func closeEnvironmentServiceRuns(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, service string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT id,run_number FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL ORDER BY id FOR UPDATE`, service)
	if err != nil {
		return err
	}
	type run struct {
		id     string
		number int64
	}
	runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (run, error) {
		var r run
		err := row.Scan(&r.id, &r.number)
		return r, err
	})
	if err != nil {
		return err
	}
	for _, r := range runs {
		if _, err = q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{ID: r.id, ServiceID: service, RunNumber: r.number, Now: timestamptz(now)}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) environmentPublisherConfiguration(ctx context.Context, tx pgx.Tx, m environmentPublisherMember) (map[string]EnvironmentServicePublication, EnvironmentPublication, error) {
	q := controlstatedb.New(tx)
	_, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey})
	if err != nil {
		return nil, EnvironmentPublication{}, err
	}
	environment, mapped, err := publisherGroupEnvironment(ctx, q, m.groupID)
	if err != nil {
		return nil, EnvironmentPublication{}, err
	}
	if !mapped || environment.ID != m.EnvironmentID || environment.TeamID != m.TeamID || environment.ProjectKey != m.ProjectKey {
		return nil, EnvironmentPublication{}, ErrEnvironmentInvalid
	}
	row, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey, ID: environment.ID})
	if err != nil {
		return nil, EnvironmentPublication{}, err
	}
	if row.RetiredAt.Valid || row.GroupID != m.groupID {
		return nil, EnvironmentPublication{}, ErrEnvironmentPublisher
	}
	_, _, services, err := d.environmentProjection(ctx, tx, row)
	publication := environmentPublication(row)
	return services, publication, err
}
