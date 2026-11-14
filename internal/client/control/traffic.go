package control

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/region"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// create a signed publisher run with the selected traffic limits; nil uses
// control's defaults.
func (c *Client) CreatePublisherRun(ctx context.Context, id, retry, token, proof string, selection *trafficlimits.Selection, protection controlv1.HTTPProtection, preferred ...string) (controlv1.PublishRunSetup, error) {
	if err := protection.Validate(); err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	body, err := publishRunRequest(selection, preferred)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	body.HttpProtection = &protection
	params := &controlv1.CreatePublishRunParams{IdempotencyKey: retry, PublisherRunProof: proof}
	return request[controlv1.PublishRunSetup](ctx, c, token, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublishRun(ctx, id, params, body, e...)
	})
}

func publishRunRequest(selection *trafficlimits.Selection, preferred []string) (controlv1.CreatePublishRunRequest, error) {
	body, err := publishRunTrafficRequest(selection)
	if err != nil {
		return body, err
	}
	preferences, err := region.Preferences(preferred)
	if err != nil {
		return body, err
	}
	if len(preferences) != 0 {
		body.PreferredRegions = &preferences
	}
	return body, nil
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
