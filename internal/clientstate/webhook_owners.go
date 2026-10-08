package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

var ErrWebhookOwned = errors.New("another live worktree owns this webhook")
var ErrWebhookReceiverUnavailable = errors.New("selected webhook receiver is not ready")
var ErrWebhookNotSelected = errors.New("this worktree is not the selected webhook receiver")

func (d *Database) ClaimWebhookReceiver(ctx context.Context, server, group, name, tunnelID string, fingerprint [32]byte, force bool) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	now := d.now().UTC().UnixNano()
	// the first write acquires SQLite ownership before checking or installing a
	// claim. expiry/release and competing claims cannot interleave this transaction.
	if err := queries.DeleteExpiredWebhookOwner(ctx, clientstatedb.DeleteExpiredWebhookOwnerParams{ServerOrigin: server, IntegrationGroup: group, Name: name, Now: now}); err != nil {
		return err
	}
	_, err = queries.ClaimWebhookReceiver(ctx, clientstatedb.ClaimWebhookReceiverParams{
		ServerOrigin: server, IntegrationGroup: group, Name: name, TunnelID: tunnelID, Fingerprint: fingerprint[:], Now: now,
	})
	if err != nil {
		return err
	}
	if force {
		ready, err := queries.ReadyExclusiveReceiver(ctx, clientstatedb.ReadyExclusiveReceiverParams{
			ServerOrigin: server, IntegrationGroup: group, Name: name, TunnelID: tunnelID, Fingerprint: fingerprint[:], Now: now,
		})
		if err != nil {
			return err
		}
		if ready != 1 {
			return ErrWebhookReceiverUnavailable
		}
		count, err := queries.ForceWebhookReceiver(ctx, clientstatedb.ForceWebhookReceiverParams{
			ServerOrigin: server, IntegrationGroup: group, Name: name, TunnelID: tunnelID,
		})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrWebhookReceiverUnavailable
		}
	}
	ownerID, err := queries.WebhookOwnerID(ctx, clientstatedb.WebhookOwnerIDParams{ServerOrigin: server, IntegrationGroup: group, Name: name, Now: now})
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

func (d *Database) ReleaseWebhookReceiver(ctx context.Context, server, group, name, tunnelID string) error {
	count, err := d.queries.ReleaseWebhookReceiver(ctx, clientstatedb.ReleaseWebhookReceiverParams{ServerOrigin: server, IntegrationGroup: group, Name: name, TunnelID: tunnelID})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrWebhookNotSelected
	}
	return nil
}

func (d *Database) ExclusiveWebhookReceiver(ctx context.Context, server, group, name string, fingerprint [32]byte) (TunnelInfo, error) {
	row, err := d.queries.ExclusiveWebhookReceiver(ctx, clientstatedb.ExclusiveWebhookReceiverParams{ServerOrigin: server, IntegrationGroup: group, Name: name, Fingerprint: fingerprint[:], Now: d.now().UTC().UnixNano()})
	if err != nil {
		return TunnelInfo{}, err
	}
	return TunnelInfo{ID: row.ID, Server: row.ServerOrigin, IntegrationGroup: row.IntegrationGroup, Hostname: row.Hostname,
		PublicURL: "https://" + row.Hostname, Target: row.Target, PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber)}, nil
}

func (d *Database) WebhookHostname(ctx context.Context, server, group string) (string, error) {
	projectKey, namespace, valid := strings.Cut(group, "\x00")
	if !valid || projectKey == "" || namespace == "" {
		return "", errors.New("invalid integration group")
	}
	return d.queries.GetWebhookHostname(ctx, clientstatedb.GetWebhookHostnameParams{ServerOrigin: server, ProjectKey: projectKey, Namespace: namespace})
}
