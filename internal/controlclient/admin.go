package controlclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) AdminServerStatus(ctx context.Context) (controlv1.AdminServerStatus, error) {
	status, err := requestWithAccess[controlv1.AdminServerStatus](ctx, c, c.api.GetAdminServerStatus)
	if err != nil {
		return controlv1.AdminServerStatus{}, err
	}
	if !status.Role.Valid() || status.StartedAt.IsZero() || status.CurrentTime.IsZero() ||
		status.EnabledPublicUrls < 0 || status.SuspendedPublicUrls < 0 || status.StartingPublishRuns < 0 ||
		status.ReadyPublishRuns < 0 || status.IngressLeases < 0 || status.RelayLeases < 0 {
		return controlv1.AdminServerStatus{}, errors.New("controlclient: server returned an invalid status")
	}
	return status, nil
}

func (c *Client) AdminListRelays(ctx context.Context) (controlv1.AdminRelayPage, error) {
	result := controlv1.AdminRelayPage{Relays: []controlv1.AdminRelayLease{}}
	cursor := ""
	for {
		params := &controlv1.ListAdminRelaysParams{}
		if cursor != "" {
			params.Cursor = &cursor
		}
		page, err := requestWithAccess[controlv1.AdminRelayPage](ctx, c, func(
			ctx context.Context,
			editors ...controlv1.RequestEditorFn,
		) (*http.Response, error) {
			return c.api.ListAdminRelays(ctx, params, editors...)
		})
		if err != nil {
			return controlv1.AdminRelayPage{}, err
		}
		result.Relays = append(result.Relays, page.Relays...)
		if page.NextCursor == nil {
			return result, nil
		}
		nextCursor := string(*page.NextCursor)
		if len(page.Relays) == 0 || nextCursor == "" || nextCursor <= cursor {
			return controlv1.AdminRelayPage{}, errors.New("controlclient: invalid relay cursor")
		}
		cursor = nextCursor
	}
}

func (c *Client) AdminDrainRelay(ctx context.Context, relayID string, body controlv1.AdminDrainRelayRequest) (controlv1.AdminRelayLease, error) {
	return requestWithAccess[controlv1.AdminRelayLease](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DrainAdminRelay(ctx, relayID, body, editors...)
	})
}

func (c *Client) AdminListMaintenanceControls(ctx context.Context) ([]controlv1.MaintenanceControl, error) {
	return requestWithAccess[[]controlv1.MaintenanceControl](ctx, c, c.api.ListMaintenanceControls)
}

func (c *Client) AdminSetMaintenanceControl(ctx context.Context, name controlv1.MaintenanceControlName, allowed bool) (controlv1.MaintenanceControl, error) {
	body := controlv1.SetMaintenanceControlRequest{Allowed: allowed}
	return requestWithAccess[controlv1.MaintenanceControl](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetMaintenanceControl(ctx, name, body, editors...)
	})
}
