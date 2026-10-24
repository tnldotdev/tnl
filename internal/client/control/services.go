package control

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) EnrollVisitorDevice(ctx context.Context, key ed25519.PublicKey) (controlv1.VisitorDevice, error) {
	return requestWithAccess[controlv1.VisitorDevice](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.EnrollVisitorDevice(ctx, controlv1.EnrollVisitorDeviceJSONRequestBody{PublicKey: hex.EncodeToString(key)}, editors...)
	})
}

func (c *Client) RevokeVisitorDevice(ctx context.Context, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeVisitorDevice(ctx, id, editors...)
	})
	return err
}

func (c *Client) CreateVisitorIngressAssignments(ctx context.Context, serviceID, deviceID, key string, preferred ...string) ([]controlv1.ConnectorSessionSetup, error) {
	body := controlv1.CreateVisitorIngressAssignmentsJSONRequestBody{DeviceId: deviceID, IdempotencyKey: key}
	if len(preferred) > 0 {
		values := controlv1.LocationPreferences(append([]string(nil), preferred...))
		body.PreferredRegions = &values
	}
	return requestWithAccess[[]controlv1.ConnectorSessionSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorIngressAssignments(ctx, serviceID, body, editors...)
	})
}

func (c *Client) CreateVisitorIngressAssignment(ctx context.Context, serviceID, deviceID, excludeIngressID, key string, preferred ...string) (controlv1.ConnectorSessionSetup, error) {
	body := controlv1.CreateVisitorIngressAssignmentJSONRequestBody{DeviceId: deviceID, IdempotencyKey: key}
	if len(preferred) > 0 {
		values := controlv1.LocationPreferences(append([]string(nil), preferred...))
		body.PreferredRegions = &values
	}
	if excludeIngressID != "" {
		body.ExcludeIngressId = &excludeIngressID
	}
	return requestWithAccess[controlv1.ConnectorSessionSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorIngressAssignment(ctx, serviceID, body, editors...)
	})
}

func (c *Client) SelectServiceRun(ctx context.Context, serviceID, deviceID string) (controlv1.ServiceSelection, error) {
	return requestWithAccess[controlv1.ServiceSelection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectServiceRun(ctx, serviceID, controlv1.SelectServiceRunJSONRequestBody{DeviceId: deviceID}, editors...)
	})
}

// a person's control session may create the saved service and issue an exact
// enrollment. the resulting publisher uses only its scoped grant for runs.
func (c *Client) CreateService(ctx context.Context, team, name, key string, metadata ...controlv1.ServiceMetadata) (controlv1.Service, error) {
	return c.CreateServiceAt(ctx, team, name, key, nil, metadata...)
}

func (c *Client) CreateServiceAt(ctx context.Context, team, name, key string, placement *controlv1.ServicePlacement, metadata ...controlv1.ServiceMetadata) (controlv1.Service, error) {
	body := controlv1.CreateServiceRequest{TeamId: team, Name: name, Placement: placement}
	if len(metadata) > 1 {
		return controlv1.Service{}, errors.New("provide one service declaration")
	}
	if len(metadata) == 1 {
		body.Protocol = &metadata[0].Protocol
		body.TargetTls = metadata[0].TargetTls
		body.PublisherPool = &metadata[0].PublisherPool
	}
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateService(ctx, &controlv1.CreateServiceParams{IdempotencyKey: key},
			body, editors...)
	})
}

func (c *Client) ListServices(ctx context.Context, team string) ([]controlv1.Service, error) {
	var all []controlv1.Service
	var cursor *string
	for {
		page, err := requestWithAccess[controlv1.ServicePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListServices(ctx, &controlv1.ListServicesParams{TeamId: team, Cursor: cursor}, editors...)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Services...)
		if page.NextCursor == nil {
			return all, nil
		}
		if len(page.Services) == 0 || cursor != nil && *cursor == *page.NextCursor {
			return nil, failure.Wrap("list services", failure.ServerResponseInvalid, errors.New("control returned an invalid service cursor"))
		}
		cursor = page.NextCursor
	}
}

// ListAvailableServices returns only services the signed-in identity
// may visit. publisher inventory and a friendly name are not visitor grants.
func (c *Client) ListAvailableServices(ctx context.Context) ([]controlv1.Service, error) {
	var all []controlv1.Service
	var cursor *controlv1.ServiceCursor
	seen := map[string]bool{}
	for {
		page, err := requestWithAccess[controlv1.ServicePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListAvailableServices(ctx, &controlv1.ListAvailableServicesParams{Cursor: cursor}, editors...)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Services...)
		if page.NextCursor == nil {
			return all, nil
		}
		if len(page.Services) == 0 || seen[*page.NextCursor] {
			return nil, failure.Wrap("list available services", failure.ServerResponseInvalid, errors.New("control returned an invalid service cursor"))
		}
		seen[*page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (c *Client) PrepareServiceRun(ctx context.Context, serviceID, key, publisherAccess string, declared controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	return request[controlv1.ServiceRunPreparation](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareServiceRun(ctx, serviceID, &controlv1.PrepareServiceRunParams{IdempotencyKey: key}, declared, editors...)
	})
}

func (c *Client) ConfigureService(ctx context.Context, id string, metadata controlv1.ServiceMetadata) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfigureService(ctx, id, metadata, editors...)
	})
}

func (c *Client) DeleteService(ctx context.Context, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteService(ctx, id, editors...)
	})
	return err
}

func (c *Client) GetService(ctx context.Context, id string) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetService(ctx, id, editors...)
	})
}

func (c *Client) GetPublisherService(ctx context.Context, publisherAccess string) (controlv1.Service, error) {
	return request[controlv1.Service](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPublisherService(ctx, editors...)
	})
}

func (c *Client) HeartbeatServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken) (controlv1.ServiceRunState, error) {
	return c.HeartbeatServiceRunHealth(ctx, serviceID, runID, token, controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 64})
}

func (c *Client) HeartbeatServiceRunHealth(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	return request[controlv1.ServiceRunState](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatServiceRun(ctx, serviceID, runID, health, editors...)
	})
}

func (c *Client) CloseServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CloseServiceRun(ctx, serviceID, runID, editors...)
	})
	return err
}
