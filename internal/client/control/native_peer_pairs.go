package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Native pair requests carry an already signed Go v1 proof. the source is
// selected here so a workload request cannot accidentally send a control bearer.
// callers retain the signed IdempotencyKey as the owner key through replacement;
// uncertain replies repeat the exact proof, never a fresh owner key.
func (c *Client) PrepareDeviceNativePeerPair(ctx context.Context, service, device string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	body.Source = source
	return requestWithAccess[controlv1.NativePeerPair](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareNativePeerPair(ctx, service, body, editors...)
	})
}

func (c *Client) RenewDeviceNativePeerPair(ctx context.Context, service, pair, device string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	body.Source = source
	return requestWithAccess[controlv1.NativePeerPair](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewNativePeerPair(ctx, service, pair, body, editors...)
	})
}

func (c *Client) PrepareWorkloadNativePeerPair(ctx context.Context, service, credential string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: credential})
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	body.Source = source
	return request[controlv1.NativePeerPair](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareNativePeerPair(ctx, service, body, editors...)
	})
}

func (c *Client) RenewWorkloadNativePeerPair(ctx context.Context, service, pair, credential string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: credential})
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	body.Source = source
	return request[controlv1.NativePeerPair](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewNativePeerPair(ctx, service, pair, body, editors...)
	})
}

func (c *Client) DeliverNativePeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	return request[controlv1.NativePeerPairDelivery](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeliverNativePeerPair(ctx, serviceID, runID, pairID, controlv1.DeliverNativePeerPairJSONRequestBody{DeliveryGeneration: generation}, editors...)
	})
}

func (c *Client) ListNativePeerPairs(ctx context.Context, serviceID, runID, after string, token credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	params := &controlv1.ListNativePeerPairsParams{}
	if after != "" {
		params.After = &after
	}
	return request[controlv1.NativePeerPairCandidates](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListNativePeerPairs(ctx, serviceID, runID, params, editors...)
	})
}

func (c *Client) ConfirmNativePeerPairPrepared(ctx context.Context, serviceID, runID, pairID string, prepared controlv1.NativePeerPairPrepared, token credentials.ServiceRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfirmNativePeerPairPrepared(ctx, serviceID, runID, pairID, prepared, editors...)
	})
	return err
}
