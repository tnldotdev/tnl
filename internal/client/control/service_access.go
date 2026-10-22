package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) InviteServiceVisitor(ctx context.Context, service, key string, body controlv1.CreateServiceInvitationRequest) (controlv1.ServiceInvitation, error) {
	return requestWithAccess[controlv1.ServiceInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.InviteServiceVisitor(ctx, service, &controlv1.InviteServiceVisitorParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) AcceptServiceInvitation(ctx context.Context, secret string) (controlv1.ServiceGrant, error) {
	return requestWithAccess[controlv1.ServiceGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptServiceInvitation(ctx, controlv1.AcceptServiceInvitationJSONRequestBody{Secret: secret}, e...)
	})
}

func (c *Client) ListServiceInvitations(ctx context.Context, service string) ([]controlv1.ServiceInvitation, error) {
	all := make([]controlv1.ServiceInvitation, 0)
	after := ""
	for {
		page, err := requestWithAccess[controlv1.ServiceInvitationPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListServiceInvitations(ctx, service, &controlv1.ListServiceInvitationsParams{Cursor: cursorString(after)}, e...)
		})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(page.Invitations))
		for _, row := range page.Invitations {
			if row.ServiceId != service || row.Secret != nil {
				return nil, invalidServiceAccessPage()
			}
			ids = append(ids, row.Id)
		}
		if page.Invitations == nil || !validServiceAccessPage(ids, after, page.NextCursor, opaqueid.ServiceInvitationPrefix) {
			return nil, invalidServiceAccessPage()
		}
		all = append(all, page.Invitations...)
		if page.NextCursor == nil {
			return all, nil
		}
		after = *page.NextCursor
	}
}

func (c *Client) RevokeServiceInvitation(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeServiceInvitation(ctx, service, id, e...)
	})
	return err
}

func (c *Client) ListServiceGrants(ctx context.Context, service string) ([]controlv1.ServiceGrant, error) {
	all := make([]controlv1.ServiceGrant, 0)
	after := ""
	for {
		page, err := requestWithAccess[controlv1.ServiceGrantPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListServiceGrants(ctx, service, &controlv1.ListServiceGrantsParams{Cursor: cursorString(after)}, e...)
		})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(page.Grants))
		for _, row := range page.Grants {
			if row.ServiceId != service || !row.Kind.Valid() {
				return nil, invalidServiceAccessPage()
			}
			ids = append(ids, row.Id)
		}
		if page.Grants == nil || !validServiceAccessPage(ids, after, page.NextCursor, opaqueid.ServiceGrantPrefix) {
			return nil, invalidServiceAccessPage()
		}
		all = append(all, page.Grants...)
		if page.NextCursor == nil {
			return all, nil
		}
		after = *page.NextCursor
	}
}

func invalidServiceAccessPage() error {
	return failure.Wrap("list service access", failure.ServerResponseInvalid, errors.New("control returned an invalid service access page"))
}

func validServiceAccessPage(ids []string, after string, next *string, prefix string) bool {
	if len(ids) > 100 {
		return false
	}
	for _, id := range ids {
		if !opaqueid.Valid(id, prefix) || id <= after {
			return false
		}
		after = id
	}
	return next == nil || len(ids) == 100 && *next == after
}

func cursorString(after string) *string {
	if after == "" {
		return nil
	}
	return &after
}

func (c *Client) RevokeServiceGrant(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeServiceGrant(ctx, service, id, e...)
	})
	return err
}
