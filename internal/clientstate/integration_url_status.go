package clientstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

// IntegrationURLInfo describes a saved project URL while its local project
// has a tunnel. readiness comes from the integration URL publisher's current lease.
type IntegrationURLInfo struct {
	Kind      string                `json:"kind"`
	Server    string                `json:"server"`
	Hostname  string                `json:"hostname"`
	PublicURL string                `json:"public_url"`
	State     string                `json:"state"`
	Reason    failure.Reason        `json:"reason,omitempty"`
	Action    string                `json:"action,omitempty"`
	Endpoints []WebhookEndpointInfo `json:"endpoints,omitempty"`
}

type WebhookEndpointInfo struct {
	Name           string                `json:"name"`
	Service        string                `json:"service"`
	Path           string                `json:"path"`
	URL            string                `json:"url"`
	Delivery       string                `json:"delivery"`
	State          string                `json:"state"`
	ReadyReceivers []WebhookReceiverInfo `json:"ready_receivers"`
	Owner          *WebhookReceiverInfo  `json:"owner,omitempty"`
	Reason         failure.Reason        `json:"reason,omitempty"`
	Action         string                `json:"action,omitempty"`
}

type WebhookReceiverInfo struct {
	TunnelID  string `json:"tunnel_id"`
	Project   string `json:"project"`
	Service   string `json:"service"`
	PublicURL string `json:"public_url,omitempty"`
	State     string `json:"state"`
}

type integrationGroupKey struct{ server, group string }
type integrationProjectKey struct{ server, project string }
type webhookStatusKey struct {
	integrationGroupKey
	name string
}

func statusReason(reason failure.Reason) (failure.Reason, string) {
	definition, _ := failure.DefinitionFor(reason)
	return reason, definition.Action
}

func (d *Database) snapshotIntegrationURLs(ctx context.Context, tx *sql.Tx, tunnels []clientstatedb.LocalTunnel, at time.Time) ([]IntegrationURLInfo, error) {
	result := []IntegrationURLInfo{}
	projects := map[integrationProjectKey]bool{}
	groups := map[integrationGroupKey]bool{}
	for _, tunnel := range tunnels {
		project, namespace, found := strings.Cut(tunnel.IntegrationGroup, "\x00")
		if !found || project == "" || namespace == "" {
			continue
		}
		projects[integrationProjectKey{tunnel.ServerOrigin, project}] = true
		groups[integrationGroupKey{tunnel.ServerOrigin, tunnel.IntegrationGroup}] = true
	}
	if len(groups) == 0 {
		return result, nil
	}
	queries := clientstatedb.New(tx)
	hostnames, err := queries.StatusIntegrationURLs(ctx)
	if err != nil {
		return nil, err
	}
	indices := map[integrationGroupKey]int{}
	for _, row := range hostnames {
		group := row.ProjectKey + "\x00" + row.Namespace
		key := integrationGroupKey{row.ServerOrigin, group}
		if row.Purpose == "hooks" && !groups[key] || row.Purpose == "oauth" && !projects[integrationProjectKey{row.ServerOrigin, row.ProjectKey}] {
			continue
		}
		kind := "webhooks"
		if row.Purpose == "oauth" {
			kind = "oauth"
		}
		url := IntegrationURLInfo{Kind: kind, Server: row.ServerOrigin, Hostname: row.Hostname,
			PublicURL: "https://" + row.Hostname, State: "ready"}
		switch {
		case row.PublisherExpiresAt == 0:
			url.State = "unavailable"
			url.Reason, url.Action = statusReason(failure.IntegrationURLNotReady)
		case row.PublisherExpiresAt <= at.UnixNano():
			url.State = "stale"
			url.Reason, url.Action = statusReason(failure.IntegrationURLLeaseExpired)
		}
		if kind == "webhooks" {
			indices[key] = len(result)
		}
		result = append(result, url)
	}
	declarations, err := queries.StatusWebhookDeclarations(ctx, at.UnixNano())
	if err != nil {
		return nil, err
	}
	endpointIndices := map[webhookStatusKey]int{}
	fingerprints := map[webhookStatusKey][32]byte{}
	conflicts := map[webhookStatusKey]bool{}
	for _, row := range declarations {
		key := webhookStatusKey{integrationGroupKey{row.ServerOrigin, row.IntegrationGroup}, row.Name}
		index, found := indices[key.integrationGroupKey]
		if !found {
			continue
		}
		url := &result[index]
		digest := sha256.Sum256(row.Definition)
		definition, decodeErr := decodeWebhook(row.Name, row.Definition)
		invalid := decodeErr != nil || !bytes.Equal(digest[:], row.Fingerprint) || definition.Path != row.Path || definition.Service != row.Service
		endpointIndex, exists := endpointIndices[key]
		if !exists {
			delivery := definition.DeliveryMode()
			url.Endpoints = append(url.Endpoints, WebhookEndpointInfo{
				Name: row.Name, Service: row.Service, Path: row.Path, URL: url.PublicURL + row.Path,
				Delivery: delivery, State: "unavailable", ReadyReceivers: []WebhookReceiverInfo{},
			})
			endpointIndex = len(url.Endpoints) - 1
			endpointIndices[key] = endpointIndex
			fingerprints[key] = digest
		} else if fingerprints[key] != digest || url.Endpoints[endpointIndex].Path != row.Path || url.Endpoints[endpointIndex].Service != row.Service {
			invalid = true
		}
		if invalid {
			conflicts[key] = true
		}
		if row.Service == row.TunnelService && row.State == string(TunnelStateReady) && row.AppHostname != "" && row.PublicURLID != "" && row.PublishRunNumber > 0 {
			url.Endpoints[endpointIndex].ReadyReceivers = append(url.Endpoints[endpointIndex].ReadyReceivers, WebhookReceiverInfo{
				TunnelID: row.TunnelID, Project: row.ProjectRoot, Service: row.TunnelService,
				PublicURL: "https://" + row.AppHostname, State: row.State,
			})
		}
	}
	owners, err := queries.StatusWebhookOwners(ctx, at.UnixNano())
	if err != nil {
		return nil, err
	}
	for _, row := range owners {
		key := webhookStatusKey{integrationGroupKey{row.ServerOrigin, row.IntegrationGroup}, row.Name}
		index, found := indices[key.integrationGroupKey]
		if !found {
			continue
		}
		endpointIndex, found := endpointIndices[key]
		if !found {
			continue
		}
		owner := &WebhookReceiverInfo{TunnelID: row.TunnelID, Project: row.ProjectRoot, Service: row.Service, State: row.State}
		if row.AppHostname != "" {
			owner.PublicURL = "https://" + row.AppHostname
		}
		result[index].Endpoints[endpointIndex].Owner = owner
	}
	for key, endpointIndex := range endpointIndices {
		url := &result[indices[key.integrationGroupKey]]
		endpoint := &url.Endpoints[endpointIndex]
		slices.SortFunc(endpoint.ReadyReceivers, func(a, b WebhookReceiverInfo) int { return strings.Compare(a.TunnelID, b.TunnelID) })
		switch {
		case conflicts[key]:
			endpoint.Reason, endpoint.Action = statusReason(failure.WebhookPolicyConflict)
		case url.State != "ready":
			endpoint.Reason, endpoint.Action = url.Reason, url.Action
		case endpoint.Delivery == "selected" && endpoint.Owner == nil:
			endpoint.Reason, endpoint.Action = statusReason(failure.WebhookOwnerMissing)
		case endpoint.Delivery == "selected" && !slices.ContainsFunc(endpoint.ReadyReceivers, func(receiver WebhookReceiverInfo) bool { return receiver.TunnelID == endpoint.Owner.TunnelID }):
			endpoint.Reason, endpoint.Action = statusReason(failure.WebhookOwnerUnready)
		case len(endpoint.ReadyReceivers) == 0:
			endpoint.Reason, endpoint.Action = statusReason(failure.WebhookNoReadyReceivers)
		default:
			endpoint.State = "ready"
		}
	}
	for index := range result {
		slices.SortFunc(result[index].Endpoints, func(a, b WebhookEndpointInfo) int { return strings.Compare(a.Name, b.Name) })
	}
	return result, nil
}
