package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

type AliasInfo struct {
	Name             string         `json:"name"`
	Server           string         `json:"server"`
	Hostname         string         `json:"hostname"`
	PublicURL        string         `json:"public_url"`
	Service          string         `json:"service"`
	SelectedProject  string         `json:"selected_project"`
	DefaultProject   string         `json:"default_project"`
	State            string         `json:"state"`
	PublicURLID      string         `json:"public_url_id,omitempty"`
	PublishRunNumber uint64         `json:"publish_run_number,omitempty"`
	Reason           failure.Reason `json:"reason,omitempty"`
	Action           string         `json:"action,omitempty"`
}

func (d *Database) snapshotAliases(ctx context.Context, tx *sql.Tx, project string, at time.Time) ([]AliasInfo, error) {
	queries := clientstatedb.New(tx)
	rows, err := queries.StatusAliases(ctx, project)
	if err != nil {
		return nil, err
	}
	result := make([]AliasInfo, 0, len(rows))
	for _, row := range rows {
		info := AliasInfo{Name: row.Name, Server: row.ServerOrigin, Hostname: row.Hostname, PublicURL: "https://" + row.Hostname,
			Service: row.Service, SelectedProject: row.SelectedProject, DefaultProject: row.ProjectKey, State: "unavailable"}
		receiver, receiverErr := queries.ReadyAliasReceiver(ctx, clientstatedb.ReadyAliasReceiverParams{
			AliasID: row.ID, ProjectRoot: row.SelectedProject, Now: at.UnixNano(),
		})
		if receiverErr != nil && !errors.Is(receiverErr, sql.ErrNoRows) {
			return nil, receiverErr
		}
		reason := failure.Reason(row.FailureReason)
		switch {
		case reason != "":
			if _, valid := failure.DefinitionFor(reason); !valid {
				reason = failure.IntegrationURLNotReady
			}
		case receiverErr != nil:
			reason = failure.AliasReceiverUnready
		case row.PublisherExpiresAt <= at.UnixNano() || receiver.ID != row.RunTunnelID || row.RunRevision != row.SelectionRevision || row.TargetProject != row.SelectedProject ||
			row.TargetState != "ready" || row.TargetExpiresAt <= at.UnixNano() || row.TargetStoppedAt != 0 ||
			row.TargetPublicURLID != row.RunTargetPublicURLID || row.TargetPublishRunNumber != row.RunTargetPublishRunNumber:
			reason = failure.IntegrationURLNotReady
		default:
			info.State, info.PublicURLID, info.PublishRunNumber = "ready", row.PublicURLID, uint64(row.PublishRunNumber)
		}
		if reason != "" {
			info.Reason, info.Action = statusReason(reason)
		}
		result = append(result, info)
	}
	return result, nil
}
