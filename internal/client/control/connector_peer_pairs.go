package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Connector pair requests carry an already signed Go v1 proof. the source is
// selected here so a workload request cannot accidentally send a control bearer.
// callers retain the signed IdempotencyKey as the owner key through replacement;
// uncertain replies repeat the exact proof, never a fresh owner key.
func (c *Client) PrepareDeviceConnectorPeerPair(ctx context.Context, service, device string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	body.Source = source
	return requestWithAccess[controlv1.ConnectorPeerPair](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareConnectorPeerPair(ctx, service, body, editors...)
	})
}

func (c *Client) RenewDeviceConnectorPeerPair(ctx context.Context, service, pair, device string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	body.Source = source
	return requestWithAccess[controlv1.ConnectorPeerPair](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewConnectorPeerPair(ctx, service, pair, body, editors...)
	})
}

func (c *Client) PrepareWorkloadConnectorPeerPair(ctx context.Context, service, credential string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: credential})
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	body.Source = source
	return request[controlv1.ConnectorPeerPair](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareConnectorPeerPair(ctx, service, body, editors...)
	})
}

func (c *Client) RenewWorkloadConnectorPeerPair(ctx context.Context, service, pair, credential string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: credential})
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	body.Source = source
	return request[controlv1.ConnectorPeerPair](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewConnectorPeerPair(ctx, service, pair, body, editors...)
	})
}

func (c *Client) DeliverConnectorPeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error) {
	return request[controlv1.ConnectorPeerPairDelivery](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeliverConnectorPeerPair(ctx, serviceID, runID, pairID, controlv1.DeliverConnectorPeerPairJSONRequestBody{DeliveryGeneration: generation}, editors...)
	})
}

func (c *Client) ListConnectorPeerPairs(ctx context.Context, serviceID, runID, after string, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	params := &controlv1.ListConnectorPeerPairsParams{}
	if after != "" {
		params.After = &after
	}
	return request[controlv1.ConnectorPeerPairCandidates](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListConnectorPeerPairs(ctx, serviceID, runID, params, editors...)
	})
}

func (c *Client) ConfirmConnectorPeerPairPrepared(ctx context.Context, serviceID, runID, pairID string, prepared controlv1.ConnectorPeerPairPrepared, token credentials.ServiceRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfirmConnectorPeerPairPrepared(ctx, serviceID, runID, pairID, prepared, editors...)
	})
	return err
}
