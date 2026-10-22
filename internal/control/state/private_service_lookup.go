package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (d *Database) ListPrivateServices(ctx context.Context, teamID, actorID, after string) ([]PrivateServiceRecord, string, error) {
	if after != "" && !opaqueid.Valid(after, opaqueid.PrivateServicePrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServicesForTeam(ctx, controlstatedb.ListPrivateServicesForTeamParams{TeamID: teamID, AfterID: after})
	if err != nil {
		return nil, "", err
	}
	result := make([]PrivateServiceRecord, 0, min(100, len(rows)))
	next := ""
	for index, row := range rows {
		if index == 100 {
			next = rows[index-1].ID
			break
		}
		record, err := checkedPrivateServiceRecord(row)
		if err != nil {
			return nil, "", err
		}
		if err = privateServiceSource(ctx, controlstatedb.New(tx), &record); err != nil {
			return nil, "", err
		}
		result = append(result, record)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) GetPrivateService(ctx context.Context, serviceID, actorID string) (result PrivateServiceRecord, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get private service", &retErr)()
	var row controlstatedb.ControlPrivateService
	if _, signed := serviceActor(ctx); signed {
		row, err = lockManagedPrivateService(ctx, tx, serviceID, actorID)
	} else {
		row, err = controlstatedb.New(tx).GetPrivateService(ctx, serviceID)
		if err == nil {
			err = privateServiceManager(ctx, tx, row.TeamID, actorID)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return PrivateServiceRecord{}, ErrPrivateServiceAccess
	} else if err != nil {
		return PrivateServiceRecord{}, err
	}
	result, err = checkedPrivateServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = privateServiceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRecord{}, err
	}
	return result, nil
}

func privateServiceSource(ctx context.Context, q *controlstatedb.Queries, record *PrivateServiceRecord) error {
	source, err := q.GetPrivateServiceSource(ctx, text(record.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	record.Source = &LocalServiceSource{ProjectKey: source.ProjectKey, SourceFingerprint: source.SourceFingerprint, Service: source.Service, WorktreeKey: source.WorktreeKey}
	return nil
}

func (d *Database) ListAvailablePrivateServices(ctx context.Context, identityID, cursor string, now time.Time) ([]PrivateServiceInventory, string, error) {
	if cursor != "" && !opaqueid.Valid(cursor, opaqueid.PrivateServicePrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	rows, err := controlstatedb.New(d.pool).ListAvailablePrivateServices(ctx, controlstatedb.ListAvailablePrivateServicesParams{
		ControlSessionID: companySessionID(ctx, identityID),
		IdentityID:       identityID, AfterID: cursor, Now: timestamptz(now),
	})
	if err != nil {
		return nil, "", fmt.Errorf("controlstate: list private services: %w", err)
	}
	page := make([]PrivateServiceInventory, 0, min(len(rows), 100))
	next := ""
	for i, row := range rows {
		if i == 100 {
			next = rows[i-1].ID
			break
		}
		metadata, err := decodePrivateMetadata(row.Protocol, row.TlsMetadata, row.PublisherPool, row.TrustRevision)
		if err != nil {
			return nil, "", err
		}
		metadata.ManagedTLS = managedServiceTLS(row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
		var kube *controlv1.KubernetesAuth
		if row.Protocol == "kubernetes" {
			kube, err = d.visitorKubernetesAuth(ctx, controlstatedb.New(d.pool), row.ID)
			if err != nil {
				return nil, "", err
			}
		}
		page = append(page, PrivateServiceInventory{PrivateServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID, Name: row.Name, CreatedAt: row.CreatedAt.Time,
			PrivateRunID: row.PrivateRunID.String, RunNumber: row.RunNumber.Int64, KubernetesAuth: kube})
	}
	return page, next, nil
}
