package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

type ProjectStatus struct {
	RetiredAt    *time.Time                 `json:"retired_at,omitempty"`
	TeamID       string                     `json:"team_id"`
	ProjectKey   string                     `json:"project_key"`
	ProjectLabel string                     `json:"project_label"`
	Revision     int64                      `json:"revision,string"`
	ObservedAt   time.Time                  `json:"observed_at"`
	Publications []ProjectPublicationStatus `json:"publications"`
	NextCursor   string                     `json:"next_cursor,omitempty"`
}

type ProjectPublicationStatus struct {
	Service                   string     `json:"service"`
	PublisherGroup            string     `json:"publisher_group"`
	Kind                      string     `json:"service_kind"`
	WorktreeKey               string     `json:"worktree_key,omitempty"`
	ServiceID                 string     `json:"service_id,omitempty"`
	PublicURLID               string     `json:"public_url_id,omitempty"`
	Hostname                  string     `json:"hostname"`
	Port                      int        `json:"port,omitempty"`
	ServiceRunID              string     `json:"service_run_id,omitempty"`
	PublishRunID              string     `json:"publish_run_id,omitempty"`
	RunNumber                 int64      `json:"run_number,omitempty,string"`
	PublicationState          string     `json:"publication_state,omitempty"`
	PublisherExpiresAt        *time.Time `json:"publisher_expires_at,omitempty"`
	CertificateExpiresAt      *time.Time `json:"certificate_expires_at,omitempty"`
	ReadyPublisherConnections int        `json:"ready_publisher_connections"`
	Ready                     bool       `json:"ready"`
	Reason                    string     `json:"reason"`
}

func (d *Database) GetProjectStatus(ctx context.Context, team, project, actor, cursor string, now time.Time) (result ProjectStatus, retErr error) {
	kind := "project-status/v1/" + project
	after, err := decodeDiscoveryCursor(cursor, kind, team, actor)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read project status", &retErr)()
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	projectRow, err := q.GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return result, err
	}
	rows, err := q.ListProjectPublications(ctx, controlstatedb.ListProjectPublicationsParams{TeamID: team, ProjectKey: project, AfterKey: after})
	if err != nil {
		return result, err
	}
	result = ProjectStatus{TeamID: team, ProjectKey: project, ProjectLabel: projectRow.ProjectLabel, Revision: projectRow.Revision, ObservedAt: now, Publications: make([]ProjectPublicationStatus, 0, min(len(rows), 100))}
	result.RetiredAt = optionalTime(projectRow.RetiredAt)
	for i, row := range rows {
		if i == 100 {
			result.NextCursor = encodeDiscoveryCursor(discoveryCursor{Kind: kind, Team: team, Actor: actor, After: rows[i-1].CursorKey})
			break
		}
		publication := ProjectPublicationStatus{Service: row.Service, PublisherGroup: row.Deployment, Kind: "local", WorktreeKey: row.WorktreeKey, ServiceID: row.ServiceID.String, PublicURLID: row.PublicURLID.String, Hostname: row.Hostname, Port: int(row.Port), RunNumber: row.RunNumber, PublicationState: row.PublicationState, PublisherExpiresAt: optionalTime(row.PublisherExpiresAt), CertificateExpiresAt: optionalTime(row.CertificateExpiresAt)}
		if row.ServiceID.Valid {
			publication.Kind, publication.ServiceRunID = "service", row.RunID
			if row.RunID != "" {
				publication.ReadyPublisherConnections, err = countReadyServiceConnections(ctx, tx, row.RunID, now)
			}
		} else if row.PublicURLID.Valid {
			publication.Kind, publication.PublishRunID = "public_url", row.RunID
			if row.RunID != "" {
				connections, e := validReadyPublisherConnections(ctx, q, row.RunID, now)
				err = e
				publication.ReadyPublisherConnections = len(connections)
			}
		}
		if err != nil {
			return result, err
		}
		publication.Reason = projectPublicationReason(row, publication.ReadyPublisherConnections, now)
		publication.Ready = publication.Reason == "ready"
		result.Publications = append(result.Publications, publication)
	}
	return result, tx.Commit(ctx)
}

func projectPublicationReason(row controlstatedb.ListProjectPublicationsRow, connections int, now time.Time) string {
	switch {
	case !row.ServiceID.Valid && !row.PublicURLID.Valid:
		return "not_realized"
	case !row.Enabled:
		return "disabled"
	case row.RunID == "":
		return "not_publishing"
	case !row.PublisherExpiresAt.Time.After(now):
		return "publisher_expired"
	case !row.CertificateExpiresAt.Valid:
		return "certificate_pending"
	case !row.CertificateExpiresAt.Time.After(now):
		return "certificate_expired"
	case !row.Healthy:
		return "publisher_unhealthy"
	case connections == 0 || !row.ReadyAt.Valid && connections < publishRunConnectionCount:
		return "connections_pending"
	case row.PublicURLID.Valid && row.DnsState != "unmanaged" && row.DnsState != "published":
		return "dns_unavailable"
	case row.PublicationState != "ready":
		return "starting"
	default:
		return "ready"
	}
}
