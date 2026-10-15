package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// CreatePublisherRunWithTraffic preserves the publisher proof boundary while
// carrying an optional selection through the typed control API request.
func (c *Client) CreatePublisherRunWithTraffic(ctx context.Context, id, retry, token, proof string, selection *trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	body, err := publishRunTrafficRequest(selection)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	params := &controlv1.CreatePublishRunParams{IdempotencyKey: retry, PublisherRunProof: proof}
	return request[controlv1.PublishRunSetup](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublishRun(ctx, id, params, body, e...)
	})
}

func publishRunTrafficRequest(selection *trafficlimits.Selection) (controlv1.CreatePublishRunRequest, error) {
	if selection == nil {
		return controlv1.CreatePublishRunRequest{}, nil
	}
	if err := selection.Validate(); err != nil {
		return controlv1.CreatePublishRunRequest{}, err
	}
	s := selection
	return controlv1.CreatePublishRunRequest{Traffic: &controlv1.TrafficSelection{
		Connections: s.Connections, Rate: s.Rate, RatePer: s.RatePer, Burst: s.Burst,
		UploadBytes: s.UploadBytes, DownloadBytes: s.DownloadBytes,
		TotalConnections: s.TotalConnections, TotalUploadBytes: s.TotalUploadBytes, TotalDownloadBytes: s.TotalDownloadBytes,
	}}, nil
}
