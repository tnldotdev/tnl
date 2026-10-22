package controlclient

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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

func (c *Client) CreateVisitorIngressAssignments(ctx context.Context, serviceID, deviceID, key string) ([]controlv1.PrivateConnectorSessionSetup, error) {
	return requestWithAccess[[]controlv1.PrivateConnectorSessionSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorIngressAssignments(ctx, serviceID, controlv1.CreateVisitorIngressAssignmentsJSONRequestBody{DeviceId: deviceID, IdempotencyKey: key}, editors...)
	})
}

func (c *Client) CreateVisitorIngressAssignment(ctx context.Context, serviceID, deviceID, excludeIngressID, key string) (controlv1.PrivateConnectorSessionSetup, error) {
	body := controlv1.CreateVisitorIngressAssignmentJSONRequestBody{DeviceId: deviceID, IdempotencyKey: key}
	if excludeIngressID != "" {
		body.ExcludeIngressId = &excludeIngressID
	}
	return requestWithAccess[controlv1.PrivateConnectorSessionSetup](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorIngressAssignment(ctx, serviceID, body, editors...)
	})
}

func (c *Client) SelectPrivateServiceRun(ctx context.Context, serviceID, deviceID string) (controlv1.PrivateServiceSelection, error) {
	return requestWithAccess[controlv1.PrivateServiceSelection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectPrivateServiceRun(ctx, serviceID, controlv1.SelectPrivateServiceRunJSONRequestBody{DeviceId: deviceID}, editors...)
	})
}

// a person's control session may create the saved service and issue an exact
// enrollment. the resulting publisher uses only its scoped grant for runs.
func (c *Client) CreatePrivateService(ctx context.Context, team, name, key string, metadata ...controlv1.PrivateServiceMetadata) (controlv1.PrivateService, error) {
	return c.CreatePrivateServiceAt(ctx, team, name, key, nil, metadata...)
}

func (c *Client) CreatePrivateServiceAt(ctx context.Context, team, name, key string, placement *controlv1.PrivateServicePlacement, metadata ...controlv1.PrivateServiceMetadata) (controlv1.PrivateService, error) {
	body := controlv1.CreatePrivateServiceRequest{TeamId: team, Name: name, Placement: placement}
	if len(metadata) > 1 {
		return controlv1.PrivateService{}, errors.New("provide one private service declaration")
	}
	if len(metadata) == 1 {
		body.Protocol = &metadata[0].Protocol
		body.TargetTls = metadata[0].TargetTls
		body.PublisherPool = &metadata[0].PublisherPool
	}
	return requestWithAccess[controlv1.PrivateService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePrivateService(ctx, &controlv1.CreatePrivateServiceParams{IdempotencyKey: key},
			body, editors...)
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

// ListAvailablePrivateServices returns only services the signed-in identity
// may visit. publisher inventory and a friendly name are not visitor grants.
func (c *Client) ListAvailablePrivateServices(ctx context.Context) ([]controlv1.PrivateService, error) {
	var all []controlv1.PrivateService
	var cursor *controlv1.PrivateServiceCursor
	seen := map[string]bool{}
	for {
		page, err := requestWithAccess[controlv1.PrivateServicePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListAvailablePrivateServices(ctx, &controlv1.ListAvailablePrivateServicesParams{Cursor: cursor}, editors...)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Services...)
		if page.NextCursor == nil {
			return all, nil
		}
		if len(page.Services) == 0 || seen[*page.NextCursor] {
			return nil, failure.Wrap("list available private services", failure.ServerResponseInvalid, errors.New("control returned an invalid private service cursor"))
		}
		seen[*page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (c *Client) PreparePrivateServiceRun(ctx context.Context, serviceID, key, publisherAccess string, metadata ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error) {
	declared := controlv1.PrivateServiceRunDeclaration{Protocol: controlv1.Tcp, TrustRevision: 1}
	if len(metadata) > 0 {
		declared = metadata[0]
	}
	return request[controlv1.PrivateServiceRunPreparation](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PreparePrivateServiceRun(ctx, serviceID, &controlv1.PreparePrivateServiceRunParams{IdempotencyKey: key}, declared, editors...)
	})
}

func (c *Client) ConfigurePrivateService(ctx context.Context, id string, metadata controlv1.PrivateServiceMetadata) (controlv1.PrivateService, error) {
	return requestWithAccess[controlv1.PrivateService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfigurePrivateService(ctx, id, metadata, editors...)
	})
}

func (c *Client) DeletePrivateService(ctx context.Context, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeletePrivateService(ctx, id, editors...)
	})
	return err
}

func (c *Client) GetPrivateService(ctx context.Context, id string) (controlv1.PrivateService, error) {
	return requestWithAccess[controlv1.PrivateService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPrivateService(ctx, id, editors...)
	})
}

func (c *Client) GetPublisherPrivateService(ctx context.Context, publisherAccess string) (controlv1.PrivateService, error) {
	return request[controlv1.PrivateService](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPublisherPrivateService(ctx, editors...)
	})
}

func (c *Client) HeartbeatPrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.ManagedRunToken) (controlv1.PrivateServiceRunState, error) {
	return c.HeartbeatPrivateServiceRunHealth(ctx, serviceID, runID, token, controlv1.PrivateServiceRunHeartbeat{Healthy: true, StreamCapacity: 64})
}

func (c *Client) HeartbeatPrivateServiceRunHealth(ctx context.Context, serviceID, runID string, token credentials.ManagedRunToken, health controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	return request[controlv1.PrivateServiceRunState](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.HeartbeatPrivateServiceRun(ctx, serviceID, runID, health, editors...)
	})
}

func (c *Client) ClosePrivateServiceRun(ctx context.Context, serviceID, runID string, token credentials.ManagedRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ClosePrivateServiceRun(ctx, serviceID, runID, editors...)
	})
	return err
}
