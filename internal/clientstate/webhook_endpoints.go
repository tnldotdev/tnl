package clientstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/config"
)

var ErrWebhookPolicyConflict = errors.New("another worktree declares a conflicting webhook path or policy")

// RegisterWebhookEndpoint declares a path for this tunnel's integration group.
// receiver selection remains separate: only the declared service receives it.
func (t *Tunnel) RegisterWebhookEndpoint(ctx context.Context, name string, definition []byte) error {
	value, err := decodeWebhook(name, definition)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(definition)
	count, err := t.database.queries.RegisterWebhookEndpoint(ctx, clientstatedb.RegisterWebhookEndpointParams{
		TunnelID: t.id, Name: name, Service: value.Service, Path: value.Path,
		Definition: definition, Fingerprint: digest[:], Now: t.database.now().UTC().UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("register webhook: %w", err)
	}
	if count != 1 {
		return ErrWebhookPolicyConflict
	}
	return nil
}

func decodeWebhook(name string, encoded []byte) (config.Webhook, error) {
	var definition config.Webhook
	if !json.Valid(encoded) {
		return definition, errors.New("invalid webhook JSON")
	}
	if len(encoded) > 64<<10 {
		return definition, errors.New("webhook definition exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definition); err != nil {
		return definition, err
	}
	services := config.Services{}
	if definition.Service != "" {
		services[definition.Service] = config.Service{}
	}
	if err := config.ValidateTNL(config.TNL{Services: services, Webhooks: map[string]config.Webhook{name: definition}}); err != nil {
		return definition, err
	}
	return definition, nil
}

func (d *Database) ActiveWebhookDefinitions(ctx context.Context, server, group string) (map[string]config.Webhook, error) {
	rows, err := d.queries.ActiveWebhookEndpoints(ctx, clientstatedb.ActiveWebhookEndpointsParams{ServerOrigin: server, IntegrationGroup: group, Now: d.now().UTC().UnixNano()})
	if err != nil {
		return nil, err
	}
	definitions := make(map[string]config.Webhook)
	digests := make(map[string][32]byte)
	for _, row := range rows {
		digest := sha256.Sum256(row.Definition)
		if !bytes.Equal(digest[:], row.Fingerprint) {
			return nil, errors.New("invalid webhook fingerprint")
		}
		if previous, ok := digests[row.Name]; ok {
			if previous != digest {
				return nil, ErrWebhookPolicyConflict
			}
			continue
		}
		definition, err := decodeWebhook(row.Name, row.Definition)
		if err != nil {
			return nil, err
		}
		if definition.Path != row.Path || definition.Service != row.Service {
			return nil, ErrWebhookPolicyConflict
		}
		definitions[row.Name], digests[row.Name] = definition, digest
	}
	return definitions, nil
}

func (d *Database) WebhookReceivers(ctx context.Context, server, group, name string, digest [32]byte) ([]TunnelInfo, error) {
	rows, err := d.queries.ReadyWebhookReceivers(ctx, clientstatedb.ReadyWebhookReceiversParams{ServerOrigin: server, IntegrationGroup: group, Name: name, Now: d.now().UTC().UnixNano()})
	if err != nil {
		return nil, err
	}
	receivers := make([]TunnelInfo, 0, len(rows))
	for _, row := range rows {
		if !bytes.Equal(row.Fingerprint, digest[:]) {
			return nil, ErrWebhookPolicyConflict
		}
		receivers = append(receivers, TunnelInfo{
			ID: row.ID, Server: row.ServerOrigin, IntegrationGroup: row.IntegrationGroup, Hostname: row.Hostname,
			Target: row.Target, PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber),
			PublicURL: "https://" + row.Hostname,
		})
	}
	return receivers, nil
}

func (d *Database) WebhookReceiverCurrent(ctx context.Context, receiver TunnelInfo) (bool, error) {
	count, err := d.queries.WebhookReceiverCurrent(ctx, clientstatedb.WebhookReceiverCurrentParams{
		TunnelID: receiver.ID, ServerOrigin: receiver.Server, Target: receiver.Target, PublicURLID: receiver.PublicURLID,
		PublishRunNumber: int64(receiver.PublishRunNumber), Now: d.now().UTC().UnixNano(),
	})
	if err != nil {
		return false, err
	}
	return count == 1, nil
}
