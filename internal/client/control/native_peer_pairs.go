package control

import (
	"context"
	"encoding/json"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Native pair requests carry an already signed Go v1 proof. the source is
// selected here so a workload request cannot accidentally send a control bearer.
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
