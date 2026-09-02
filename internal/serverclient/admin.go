package serverclient

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func (c *Client) AdminServerStatus(ctx context.Context) (serverv1.AdminServerStatus, error) {
	return requestWithAccess[serverv1.AdminServerStatus](ctx, c, c.api.GetAdminServerStatus)
}

func (c *Client) AdminListRoutes(ctx context.Context, cursor string) (serverv1.AdminRoutePage, error) {
	params := &serverv1.ListAdminRoutesParams{}
	if cursor != "" {
		params.Cursor = &cursor
	}
	page, err := requestWithAccess[serverv1.AdminRoutePage](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAdminRoutes(ctx, params, editors...)
	})
	if err == nil {
		err = validateAdminRoutePage(page, cursor)
	}
	return page, err
}

func (c *Client) AdminRoute(ctx context.Context, routeID string) (serverv1.AdminRoute, error) {
	return requestWithAccess[serverv1.AdminRoute](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetAdminRoute(ctx, routeID, editors...)
	})
}

func (c *Client) AdminSuspendRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	reason string,
) (serverv1.AdminRoute, error) {
	if !validAdminRevision(revision) || !validAdminReason(reason) {
		return serverv1.AdminRoute{}, errors.New("serverclient: invalid admin route suspension")
	}
	body := serverv1.SuspendAdminRouteRequest{Revision: int(revision), Reason: reason}
	return requestWithAccess[serverv1.AdminRoute](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SuspendAdminRoute(ctx, routeID, body, editors...)
	})
}

func (c *Client) AdminResumeRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
) (serverv1.AdminRoute, error) {
	if !validAdminRevision(revision) {
		return serverv1.AdminRoute{}, errors.New("serverclient: invalid admin route revision")
	}
	body := serverv1.ResumeAdminRouteRequest{Revision: int(revision)}
	return requestWithAccess[serverv1.AdminRoute](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ResumeAdminRoute(ctx, routeID, body, editors...)
	})
}

func (c *Client) AdminListHostnames(ctx context.Context, cursor string) (serverv1.AdminHostnamePage, error) {
	params := &serverv1.ListAdminHostnamesParams{}
	if cursor != "" {
		params.Cursor = &cursor
	}
	page, err := requestWithAccess[serverv1.AdminHostnamePage](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAdminHostnames(ctx, params, editors...)
	})
	if err == nil {
		err = validateAdminHostnamePage(page, cursor)
	}
	return page, err
}

func (c *Client) AdminHostname(ctx context.Context, hostnameID string) (serverv1.AdminHostname, error) {
	return requestWithAccess[serverv1.AdminHostname](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetAdminHostname(ctx, hostnameID, editors...)
	})
}

func (c *Client) AdminRemoveHostname(ctx context.Context, hostnameID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RemoveAdminHostname(ctx, hostnameID, editors...)
	})
	return err
}

func (c *Client) AdminQuarantineHostname(ctx context.Context, hostnameID, reason string) error {
	if !validAdminReason(reason) {
		return errors.New("serverclient: invalid admin quarantine reason")
	}
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.QuarantineAdminHostname(ctx, hostnameID, serverv1.AdminReasonRequest{Reason: reason}, editors...)
	})
	return err
}

func (c *Client) AdminListCredentials(ctx context.Context, cursor string) (serverv1.AdminCredentialPage, error) {
	params := &serverv1.ListAdminCredentialsParams{}
	if cursor != "" {
		params.Cursor = &cursor
	}
	page, err := requestWithAccess[serverv1.AdminCredentialPage](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAdminCredentials(ctx, params, editors...)
	})
	if err == nil {
		err = validateAdminCredentialPage(page, cursor)
	}
	return page, err
}

func (c *Client) AdminRevokeCredential(ctx context.Context, credentialID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeAdminCredential(ctx, credentialID, editors...)
	})
	return err
}

func (c *Client) AdminListControlSessions(ctx context.Context, cursor string) (serverv1.AdminControlSessionPage, error) {
	params := &serverv1.ListAdminControlSessionsParams{}
	if cursor != "" {
		params.Cursor = &cursor
	}
	page, err := requestWithAccess[serverv1.AdminControlSessionPage](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAdminControlSessions(ctx, params, editors...)
	})
	if err == nil {
		err = validateAdminControlSessionPage(page, cursor)
	}
	return page, err
}

func (c *Client) AdminRevokeControlSession(ctx context.Context, sessionID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeAdminControlSession(ctx, sessionID, editors...)
	})
	return err
}

func (c *Client) AdminListMaintenanceControls(ctx context.Context) ([]serverv1.AdminMaintenanceControl, error) {
	values, err := requestWithAccess[[]serverv1.AdminMaintenanceControl](ctx, c, c.api.ListAdminMaintenanceControls)
	if err == nil {
		err = validateAdminMaintenanceControls(values)
	}
	return values, err
}

func (c *Client) AdminSetMaintenanceControl(
	ctx context.Context,
	name serverv1.MaintenanceControlName,
	enabled bool,
) (serverv1.AdminMaintenanceControl, error) {
	body := serverv1.SetAdminMaintenanceControlRequest{Enabled: enabled}
	return requestWithAccess[serverv1.AdminMaintenanceControl](ctx, c, func(ctx context.Context, editors ...serverv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetAdminMaintenanceControl(ctx, name, body, editors...)
	})
}

func RequireAdministrationCapability(capabilities serverv1.Capabilities) error {
	if capabilities.Administration.Version != serverv1.AdministrationCapabilitiesVersionN1 {
		return ErrUnsupported
	}
	if len(capabilities.Administration.Operations) != 6 {
		return ErrUnsupported
	}
	seen := make(map[serverv1.AdministrationCapabilitiesOperations]bool, 6)
	for _, operation := range capabilities.Administration.Operations {
		if !operation.Valid() || seen[operation] {
			return errors.New("serverclient: invalid administration capability")
		}
		seen[operation] = true
	}
	return nil
}

func validateAdminRoutePage(page serverv1.AdminRoutePage, cursor string) error {
	ids := make([]string, len(page.Routes))
	for index, route := range page.Routes {
		ids[index] = string(route.Id)
		if !route.Status.Valid() || route.RouteVersion < 1 || route.SuspensionRevision < 0 {
			return errors.New("serverclient: invalid admin route page")
		}
	}
	var next *string
	if page.NextCursor != nil {
		value := string(*page.NextCursor)
		next = &value
	}
	return validateAdminPage(ids, cursor, next, validAdminRouteID, "route")
}

func validateAdminHostnamePage(page serverv1.AdminHostnamePage, cursor string) error {
	ids := make([]string, len(page.Hostnames))
	for index, hostname := range page.Hostnames {
		ids[index] = string(hostname.Id)
		if !hostname.Kind.Valid() || !hostname.Status.Valid() ||
			(hostname.Source != "generated" && hostname.Source != "user") {
			return errors.New("serverclient: invalid admin hostname page")
		}
	}
	var next *string
	if page.NextCursor != nil {
		value := string(*page.NextCursor)
		next = &value
	}
	return validateAdminPage(ids, cursor, next, validHostnameID, "hostname")
}

func validateAdminCredentialPage(page serverv1.AdminCredentialPage, cursor string) error {
	ids := make([]string, len(page.Credentials))
	for index, credential := range page.Credentials {
		ids[index] = string(credential.Id)
		if !validAdminRouteID(string(credential.RouteId)) {
			return errors.New("serverclient: invalid admin credential page")
		}
	}
	var next *string
	if page.NextCursor != nil {
		value := string(*page.NextCursor)
		next = &value
	}
	return validateAdminPage(ids, cursor, next, validAdminCredentialID, "credential")
}

func validateAdminControlSessionPage(page serverv1.AdminControlSessionPage, cursor string) error {
	ids := make([]string, len(page.ControlSessions))
	for index, session := range page.ControlSessions {
		ids[index] = string(session.Id)
		grants := make([]string, len(session.Grants))
		for grantIndex, grant := range session.Grants {
			grants[grantIndex] = string(grant)
		}
		if !validGrants(grants) ||
			(session.AuthenticationMethod != "login_token" && session.AuthenticationMethod != "oidc") {
			return errors.New("serverclient: invalid admin control-session page")
		}
	}
	var next *string
	if page.NextCursor != nil {
		value := string(*page.NextCursor)
		next = &value
	}
	return validateAdminPage(ids, cursor, next, validControlSessionID, "control-session")
}

func validateAdminPage(
	ids []string,
	cursor string,
	next *string,
	valid func(string) bool,
	resource string,
) error {
	if len(ids) > 100 {
		return errors.New("serverclient: oversized admin " + resource + " page")
	}
	previous := cursor
	for _, id := range ids {
		if !valid(id) || id <= previous {
			return errors.New("serverclient: invalid admin " + resource + " page")
		}
		previous = id
	}
	if next != nil && (len(ids) == 0 || *next != ids[len(ids)-1]) {
		return errors.New("serverclient: invalid admin " + resource + " cursor")
	}
	return nil
}

func validateAdminMaintenanceControls(values []serverv1.AdminMaintenanceControl) error {
	if len(values) != 3 {
		return errors.New("serverclient: invalid maintenance controls")
	}
	seen := make(map[serverv1.MaintenanceControlName]bool, 3)
	for _, value := range values {
		if !value.Name.Valid() || value.Revision < 1 || seen[value.Name] {
			return errors.New("serverclient: invalid maintenance controls")
		}
		seen[value.Name] = true
	}
	return nil
}

func validAdminRouteID(value string) bool {
	return validAdminPrefixedHex(value, "route_")
}

func validAdminCredentialID(value string) bool {
	_, err := credentials.ParseCredentialID(value)
	return err == nil
}

func validAdminPrefixedHex(value, prefix string) bool {
	return opaqueid.Valid(value, prefix)
}

func validAdminRevision(revision uint64) bool {
	return revision > 0 && revision <= uint64(int(^uint(0)>>1))
}

func validAdminReason(reason string) bool {
	return reason != "" && len(reason) <= 256 && strings.TrimSpace(reason) == reason
}
