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

func (d *Database) ListServices(ctx context.Context, teamID, actorID, after string) (_ []ServiceRecord, _ string, retErr error) {
	if after != "" && !opaqueid.Valid(after, opaqueid.ServicePrefix) {
		return nil, "", ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "list services", &retErr)()
	if err = serviceManager(ctx, tx, teamID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListServicesForTeam(ctx, controlstatedb.ListServicesForTeamParams{TeamID: text(teamID), AfterID: after})
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
	row, err := serviceForManagement(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
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

func serviceForManagement(ctx context.Context, tx pgx.Tx, serviceID, actorID string) (controlstatedb.ControlService, error) {
	var row controlstatedb.ControlService
	var err error
	if _, signed := serviceActor(ctx); signed {
		row, err = lockManagedService(ctx, tx, serviceID, actorID)
	} else {
		row, err = controlstatedb.New(tx).GetService(ctx, serviceID)
		if err == nil {
			var member serviceMembership
			member, err = serviceMembershipForActor(ctx, tx, row.TeamID.String, actorID, time.Now())
			if err == nil {
				err = requireServiceManagement(ctx, tx, row, member)
			}
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return row, ErrServiceAccess
	}
	return row, err
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

func (d *Database) ListAvailableServices(ctx context.Context, identityID, cursor string, path controlv1.ServiceAccessPath, now time.Time) (_ []ServiceInventory, _ string, retErr error) {
	if !path.Valid() || cursor != "" && !opaqueid.Valid(cursor, opaqueid.ServicePrefix) {
		return nil, "", ErrServiceAccess
	}
	// HTTP identity permission locks the current person. retain the caller's
	// real control-session context and one snapshot across sparse candidate scans.
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "list available services", &retErr)()
	q := controlstatedb.New(tx)
	page := make([]ServiceInventory, 0, 100)
	after := cursor
	for {
		rows, err := q.ListAvailableServices(ctx, controlstatedb.ListAvailableServicesParams{
			ControlSessionID: companySessionID(ctx, identityID), AccessPath: string(path),
			IdentityID: identityID, AfterID: after, Now: timestamptz(now),
		})
		if err != nil {
			return nil, "", fmt.Errorf("controlstate: list services: %w", err)
		}
		for _, row := range rows {
			after = row.ID
			reason := row.VisitorAccess
			if path == controlv1.ServiceAccessPathPublicEndpoint && row.Protocol == "http" {
				permission, err := d.serviceHTTPIdentityPermission(ctx, tx, row.ID, identityID, now)
				if errors.Is(err, ErrServiceAccess) || errors.Is(err, ErrVisitorSignIn) {
					continue
				}
				if err != nil {
					return nil, "", err
				}
				// anonymous traffic permission does not grant discovery.
				if !permission.VisitAllowed || permission.Reason == "" || permission.Reason == "anonymous" {
					continue
				}
				reason = permission.Reason
			}
			metadata := ServiceMetadata{Protocol: row.Protocol, PublisherPool: row.PublisherPool, TrustRevision: row.TrustRevision,
				Endpoint: managedServiceTLS(row.Protocol, row.CertificateHostname, int(row.ServicePort.Int32), row.Public)}
			if path == controlv1.ServiceAccessPathPublicEndpoint && (metadata.Endpoint == nil || !metadata.Endpoint.Public) {
				continue
			}
			// look ahead only after authorization. resume from the last returned
			// service, never from a denied candidate or the unreturned lookahead.
			if len(page) == 100 {
				if err := tx.Commit(ctx); err != nil {
					return nil, "", err
				}
				return page, page[len(page)-1].ID, nil
			}
			var kube *controlv1.KubernetesAuth
			if row.Protocol == "kubernetes" {
				kube, err = d.visitorKubernetesAuth(ctx, q, row.ID)
				if err != nil {
					return nil, "", err
				}
			}
			page = append(page, ServiceInventory{ServiceMetadata: metadata, ID: row.ID, TeamID: row.TeamID.String, TeamName: row.TeamName, VisitorAccess: reason,
				Name: row.Name, CreatedAt: row.CreatedAt.Time, ServiceRunID: row.ServiceRunID.String, RunNumber: row.RunNumber.Int64, KubernetesAuth: kube})
		}
		if len(rows) < 101 {
			break
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return page, "", nil
}
