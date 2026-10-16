package controlclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// a person's control session may create the saved service and issue an exact
// enrollment. the resulting publisher uses only its scoped grant for runs.
func (c *Client) CreatePrivateService(ctx context.Context, team, name, key string) (controlv1.PrivateService, error) {
	return requestWithAccess[controlv1.PrivateService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePrivateService(ctx, &controlv1.CreatePrivateServiceParams{IdempotencyKey: key},
			controlv1.CreatePrivateServiceRequest{TeamId: team, Name: name}, editors...)
	})
}

func (c *Client) ListPrivateServices(ctx context.Context, team string) ([]controlv1.PrivateService, error) {
	var all []controlv1.PrivateService
	var cursor *string
	for {
		page, err := requestWithAccess[controlv1.PrivateServicePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListPrivateServices(ctx, &controlv1.ListPrivateServicesParams{TeamId: team, Cursor: cursor}, editors...)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Services...)
		if page.NextCursor == nil {
			return all, nil
		}
		if len(page.Services) == 0 || cursor != nil && *cursor == *page.NextCursor {
			return nil, failure.Wrap("list private services", failure.ServerResponseInvalid, errors.New("control returned an invalid private service cursor"))
		}
		cursor = page.NextCursor
	}
}

func (c *Client) PreparePrivateServiceRun(ctx context.Context, serviceID, key, publisherAccess string) (controlv1.PrivateServiceRunPreparation, error) {
	return request[controlv1.PrivateServiceRunPreparation](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PreparePrivateServiceRun(ctx, serviceID, &controlv1.PreparePrivateServiceRunParams{IdempotencyKey: key}, editors...)
	})
}

func (c *Client) BindPrivateServiceRunKey(ctx context.Context, serviceID, runID, publisherAccess string, body controlv1.BindPrivateServiceRunKeyRequest) (controlv1.PrivateServiceRunSetup, error) {
	return request[controlv1.PrivateServiceRunSetup](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.BindPrivateServiceRunKey(ctx, serviceID, runID, body, editors...)
	})
}

func (c *Client) HeartbeatPrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error) {
	return request[controlv1.PrivateServiceRunState](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatPrivateServiceRun(ctx, serviceID, runID, editors...)
	})
}

func (c *Client) ClosePrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.PublishRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ClosePrivateServiceRun(ctx, serviceID, runID, editors...)
	})
	return err
}
