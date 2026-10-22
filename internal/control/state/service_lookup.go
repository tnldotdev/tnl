package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (d *Database) ListServices(ctx context.Context, teamID, actorID, after string) ([]ServiceRecord, string, error) {
	if after != "" && !opaqueid.Valid(after, opaqueid.ServicePrefix) {
		return nil, "", ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	if err = serviceManager(ctx, tx, teamID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListServicesForTeam(ctx, controlstatedb.ListServicesForTeamParams{TeamID: teamID, AfterID: after})
	if err != nil {
		return nil, "", err
	}
	result := make([]ServiceRecord, 0, min(100, len(rows)))
	next := ""
	for index, row := range rows {
		if index == 100 {
			next = rows[index-1].ID
			break
		}
		record, err := checkedServiceRecord(row)
		if err != nil {
			return nil, "", err
		}
		if err = serviceSource(ctx, controlstatedb.New(tx), &record); err != nil {
			return nil, "", err
		}
		result = append(result, record)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) GetService(ctx context.Context, serviceID, actorID string) (result ServiceRecord, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return result, ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get service", &retErr)()
	var row controlstatedb.ControlService
	if _, signed := serviceActor(ctx); signed {
		row, err = lockService(ctx, tx, serviceID, actorID)
	} else {
		row, err = controlstatedb.New(tx).GetService(ctx, serviceID)
		if err == nil {
			err = serviceManager(ctx, tx, row.TeamID, actorID)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceRecord{}, ErrServiceAccess
	} else if err != nil {
		return ServiceRecord{}, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if err = serviceSource(ctx, controlstatedb.New(tx), &result); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}

func serviceSource(ctx context.Context, q *controlstatedb.Queries, record *ServiceRecord) error {
	source, err := q.GetServiceSource(ctx, text(record.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	record.Source = &LocalServiceSource{ProjectKey: source.ProjectKey, SourceFingerprint: source.SourceFingerprint, Service: source.Service, WorktreeKey: source.WorktreeKey}
	return nil
}

func (d *Database) ListAvailableServices(ctx context.Context, identityID, cursor string, now time.Time) ([]ServiceInventory, string, error) {
	if cursor != "" && !opaqueid.Valid(cursor, opaqueid.ServicePrefix) {
		return nil, "", ErrServiceAccess
	}
	rows, err := controlstatedb.New(d.pool).ListAvailableServices(ctx, controlstatedb.ListAvailableServicesParams{
		ControlSessionID: companySessionID(ctx, identityID),
		IdentityID:       identityID, AfterID: cursor, Now: timestamptz(now),
	})
	if err != nil {
		return nil, "", fmt.Errorf("controlstate: list services: %w", err)
	}
	page := make([]ServiceInventory, 0, min(len(rows), 100))
	next := ""
	for i, row := range rows {
		if i == 100 {
			next = rows[i-1].ID
			break
		}
		metadata, err := decodeServiceMetadata(row.Protocol, row.TlsMetadata, row.PublisherPool, row.TrustRevision)
		if err != nil {
			return nil, "", err
		}
		metadata.Endpoint = managedServiceTLS(row.CertificateHostname, int(row.ServicePort.Int32), row.Public)
		var kube *controlv1.KubernetesAuth
		if row.Protocol == "kubernetes" {
			kube, err = d.visitorKubernetesAuth(ctx, controlstatedb.New(d.pool), row.ID)
			if err != nil {
				return nil, "", err
			}
		}
		page = append(page, ServiceInventory{ServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID, Name: row.Name, CreatedAt: row.CreatedAt.Time,
			ServiceRunID: row.ServiceRunID.String, RunNumber: row.RunNumber.Int64, KubernetesAuth: kube})
	}
	return page, next, nil
}
