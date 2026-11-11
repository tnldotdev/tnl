package state

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

var ErrWebhookOwned = errors.New("another running tunnel is selected for this webhook")
var ErrWebhookReceiverUnavailable = errors.New("selected webhook receiver is not ready")
var ErrWebhookNotSelected = errors.New("this worktree is not the selected webhook receiver")

func (d *Database) ClaimWebhookReceiver(ctx context.Context, server string, scope IntegrationScope, name, tunnelID string, fingerprint [32]byte, force bool) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	now := d.now().UTC().UnixNano()
	// the first write acquires SQLite ownership before checking or installing a
	// claim. expiry/release and competing claims cannot interleave this transaction.
	if err := queries.DeleteExpiredWebhookOwner(ctx, clientstatedb.DeleteExpiredWebhookOwnerParams{ServerOrigin: server,
		PrimaryProjectRoot: scope.PrimaryProjectRoot, IntegrationNamespace: scope.Namespace, Name: name, Now: now}); err != nil {
		return err
	}
	_, err = queries.ClaimWebhookReceiver(ctx, clientstatedb.ClaimWebhookReceiverParams{
		ServerOrigin: server, PrimaryProjectRoot: scope.primaryProjectRoot(), IntegrationNamespace: scope.namespace(), Name: name, TunnelID: tunnelID, Fingerprint: fingerprint[:], Now: now,
	})
	if err != nil {
		return err
	}
	if force {
		ready, err := queries.ReadyExclusiveReceiver(ctx, clientstatedb.ReadyExclusiveReceiverParams{
			ServerOrigin: server, PrimaryProjectRoot: scope.primaryProjectRoot(), IntegrationNamespace: scope.namespace(), Name: name, TunnelID: tunnelID, Fingerprint: fingerprint[:], Now: now,
		})
		if err != nil {
			return err
		}
		if ready != 1 {
			return ErrWebhookReceiverUnavailable
		}
		count, err := queries.ForceWebhookReceiver(ctx, clientstatedb.ForceWebhookReceiverParams{
			ServerOrigin: server, PrimaryProjectRoot: scope.PrimaryProjectRoot, IntegrationNamespace: scope.Namespace, Name: name, TunnelID: tunnelID,
		})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrWebhookReceiverUnavailable
		}
	}
	ownerID, err := queries.WebhookOwnerID(ctx, clientstatedb.WebhookOwnerIDParams{ServerOrigin: server,
		PrimaryProjectRoot: scope.PrimaryProjectRoot, IntegrationNamespace: scope.Namespace, Name: name, Now: now})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWebhookReceiverUnavailable
	}
	if err != nil {
		return err
	}
	if ownerID != tunnelID {
		return ErrWebhookOwned
	}
	return tx.Commit()
}

func (d *Database) ReleaseWebhookReceiver(ctx context.Context, server string, scope IntegrationScope, name, tunnelID string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	count, err := d.queries.ReleaseWebhookReceiver(ctx, clientstatedb.ReleaseWebhookReceiverParams{ServerOrigin: server,
		PrimaryProjectRoot: scope.PrimaryProjectRoot, IntegrationNamespace: scope.Namespace, Name: name, TunnelID: tunnelID})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrWebhookNotSelected
	}
	return nil
}

func (d *Database) ExclusiveWebhookReceiver(ctx context.Context, server string, scope IntegrationScope, name string, fingerprint [32]byte) (TunnelInfo, error) {
	if err := scope.Validate(); err != nil {
		return TunnelInfo{}, err
	}
	row, err := d.queries.ExclusiveWebhookReceiver(ctx, clientstatedb.ExclusiveWebhookReceiverParams{ServerOrigin: server,
		PrimaryProjectRoot: scope.PrimaryProjectRoot, IntegrationNamespace: scope.Namespace, Name: name, Fingerprint: fingerprint[:], Now: d.now().UTC().UnixNano()})
	if err != nil {
		return TunnelInfo{}, err
	}
	return TunnelInfo{ID: row.ID, Server: row.ServerOrigin, IntegrationScope: IntegrationScope{PrimaryProjectRoot: row.PrimaryProjectRoot.String, Namespace: row.IntegrationNamespace.String}, Hostname: row.Hostname.String,
		PublicURL: "https://" + row.Hostname.String, Target: row.Target.String,
		PublicURLID: row.PublicURLID.String, PublishRunNumber: uint64(row.PublishRunNumber.Int64)}, nil
}

func (d *Database) WebhookHostname(ctx context.Context, server string, scope IntegrationScope) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	return d.queries.GetWebhookHostname(ctx, clientstatedb.GetWebhookHostnameParams{ServerOrigin: server, ProjectKey: scope.PrimaryProjectRoot, Namespace: scope.Namespace})
}
