package control

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/region"

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

func (c *Client) SelectServiceRun(ctx context.Context, serviceID, deviceID string) (controlv1.ServiceSelection, error) {
	return requestWithAccess[controlv1.ServiceSelection](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectServiceRun(ctx, serviceID, controlv1.SelectServiceRunJSONRequestBody{DeviceId: deviceID}, editors...)
	})
}

// a person's control session may create the saved service and issue an exact
// enrollment. the resulting publisher uses only its scoped grant for runs.
func (c *Client) CreateService(ctx context.Context, team, name, key string, metadata controlv1.ServiceMetadata, configuration *controlv1.ProjectServiceConfiguration) (controlv1.Service, error) {
	return c.CreateServiceAt(ctx, team, name, key, nil, metadata, configuration)
}

func (c *Client) CreateServiceAt(ctx context.Context, team, name, key string, placement *controlv1.ServicePlacement, metadata controlv1.ServiceMetadata, configuration *controlv1.ProjectServiceConfiguration) (controlv1.Service, error) {
	service, _, err := c.createServiceAt(ctx, team, name, key, placement, metadata, configuration, false)
	return service, err
}

// reserve uses the canonical creation operation's exact recovery decision. it
// never needs team inventory or a separate hostname lookup API.
func (c *Client) ReserveServiceAt(ctx context.Context, team, name, key string, placement *controlv1.ServicePlacement, metadata controlv1.ServiceMetadata, configuration *controlv1.ProjectServiceConfiguration) (controlv1.Service, bool, error) {
	return c.createServiceAt(ctx, team, name, key, placement, metadata, configuration, true)
}

func (c *Client) createServiceAt(ctx context.Context, team, name, key string, placement *controlv1.ServicePlacement, metadata controlv1.ServiceMetadata, configuration *controlv1.ProjectServiceConfiguration, reserve bool) (controlv1.Service, bool, error) {
	body := controlv1.CreateServiceRequest{TeamId: team, Name: name, Placement: placement,
		TargetTls: metadata.TargetTls, PublisherPool: &metadata.PublisherPool, Configuration: configuration}
	if reserve {
		body.Reserve = new(true)
	}
	if metadata.Protocol != "" {
		body.Protocol = &metadata.Protocol
	}
	created := false
	service, err := requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		response, err := c.api.CreateService(ctx, &controlv1.CreateServiceParams{IdempotencyKey: key}, body, editors...)
		created = response != nil && response.StatusCode == http.StatusCreated
		return response, err
	})
	return service, created, err
}

func (c *Client) ListServices(ctx context.Context, team string) ([]controlv1.ServiceSummary, error) {
	all := make([]controlv1.ServiceSummary, 0)
	var cursor *string
	seen := map[string]bool{}
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
		if len(page.Services) == 0 || *page.NextCursor == "" || seen[*page.NextCursor] {
			return nil, failure.Wrap("list services", failure.ServerResponseInvalid, errors.New("control returned an invalid service cursor"))
		}
		seen[*page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (c *Client) GetServiceByHostname(ctx context.Context, team, hostname string) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetServiceByHostname(ctx, hostname, &controlv1.GetServiceByHostnameParams{TeamId: team}, editors...)
	})
}

// ListAvailableServices requests one explicit visitor access path. a public HTTP
// preview grant does not authorize connector discovery or traffic.
func (c *Client) ListAvailableServices(ctx context.Context, path controlv1.ServiceAccessPath) ([]controlv1.ServiceSummary, error) {
	if !path.Valid() {
		return nil, failure.Wrap("select service access path", failure.ServerRequestInvalid, errors.New("select connector or public_endpoint access"))
	}
	all := make([]controlv1.ServiceSummary, 0)
	var cursor *controlv1.ServiceCursor
	seen := map[string]bool{}
	for {
		page, err := requestWithAccess[controlv1.ServicePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListAvailableServices(ctx, &controlv1.ListAvailableServicesParams{Cursor: cursor, AccessPath: &path}, editors...)
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Services...)
		if page.NextCursor == nil {
			return all, nil
		}
		if len(page.Services) == 0 || *page.NextCursor == "" || seen[*page.NextCursor] {
			return nil, failure.Wrap("list available services", failure.ServerResponseInvalid, errors.New("control returned an invalid service cursor"))
		}
		seen[*page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (c *Client) PrepareServiceRun(ctx context.Context, serviceID, key, publisherAccess string, declared controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	if declared.PreferredRegions != nil {
		preferences, err := region.Preferences(*declared.PreferredRegions)
		if err != nil {
			return controlv1.ServiceRunPreparation{}, err
		}
		declared.PreferredRegions = &preferences
	}
	return request[controlv1.ServiceRunPreparation](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareServiceRun(ctx, serviceID, &controlv1.PrepareServiceRunParams{IdempotencyKey: key}, declared, editors...)
	})
}

func (c *Client) ConfigureService(ctx context.Context, id string, body controlv1.UpdateServiceRequest) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfigureService(ctx, id, body, editors...)
	})
}

func (c *Client) DeleteService(ctx context.Context, id string, conditions controlv1.DeleteServiceParams) error {
	if (conditions.ExpectedServiceRevision != nil) == (conditions.UnconditionalDelete != nil) ||
		conditions.ExpectedServiceRevision != nil && *conditions.ExpectedServiceRevision < 1 ||
		conditions.UnconditionalDelete != nil && !*conditions.UnconditionalDelete {
		return failure.Wrap("delete service", failure.ServerRequestInvalid, errors.New("send exactly one positive expected service revision or explicit unconditional deletion"))
	}
	if conditions.ExpectedServiceRevision != nil {
		conditions.ExpectedServiceRevision = new(*conditions.ExpectedServiceRevision)
	}
	if conditions.UnconditionalDelete != nil {
		conditions.UnconditionalDelete = new(*conditions.UnconditionalDelete)
	}
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteService(ctx, id, &conditions, editors...)
	})
	return err
}

// guest cleanup carries the trial credential and exact service, not management
// CAS. the server checks source, ownership, and fixed trial lifetime.
func (c *Client) DeleteGuestService(ctx context.Context, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeleteService(ctx, id, nil, editors...)
	})
	return err
}

func (c *Client) SetServiceEnabled(ctx context.Context, id string, enabled bool) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetServiceEnabled(ctx, id, controlv1.SetServiceEnabledRequest{Enabled: &enabled}, editors...)
	})
}

func (c *Client) ReleaseServiceEndpoint(ctx context.Context, id string, body controlv1.ReleaseServiceEndpointRequest) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReleaseServiceEndpoint(ctx, id, body, editors...)
	})
}

func (c *Client) GetService(ctx context.Context, id string) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetService(ctx, id, editors...)
	})
}

func (c *Client) GetServiceConfiguration(ctx context.Context, id string) (*controlv1.ProjectServiceConfiguration, string, error) {
	var etags []string
	var status int
	declaration, err := requestWithAccess[*controlv1.ProjectServiceConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		response, err := c.api.GetServiceConfiguration(ctx, id, editors...)
		if err == nil {
			etags, status = response.Header.Values("ETag"), response.StatusCode
		}
		return response, err
	})
	if err != nil {
		return nil, "", err
	}
	invalid := func() (*controlv1.ProjectServiceConfiguration, string, error) {
		return nil, "", failure.Wrap("read service configuration", failure.ServerResponseInvalid, errors.New("control returned an invalid service configuration response or ETag"))
	}
	if status != http.StatusOK && status != http.StatusNoContent || len(etags) != 1 {
		return invalid()
	}
	tag := etags[0]
	if len(tag) != 73 || !strings.HasPrefix(tag, `"sha256:`) || tag[72] != '"' || strings.ToLower(tag) != tag {
		return invalid()
	}
	if _, err := hex.DecodeString(tag[8:72]); err != nil {
		return invalid()
	}
	return declaration, tag[1:72], nil
}

func (c *Client) GetPublisherService(ctx context.Context, serviceID, publisherAccess string) (controlv1.Service, error) {
	return request[controlv1.Service](ctx, c, publisherAccess, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPublisherService(ctx, serviceID, editors...)
	})
}

func (c *Client) HeartbeatServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	return request[controlv1.ServiceRunState](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewServiceRun(ctx, serviceID, runID, health, editors...)
	})
}

func (c *Client) CloseServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken) error {
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CloseServiceRun(ctx, serviceID, runID, editors...)
	})
	return err
}
