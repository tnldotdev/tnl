package controlclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) InvitePrivateServiceVisitor(ctx context.Context, service, key string, body controlv1.CreatePrivateServiceInvitationRequest) (controlv1.PrivateServiceInvitation, error) {
	return requestWithAccess[controlv1.PrivateServiceInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.InvitePrivateServiceVisitor(ctx, service, &controlv1.InvitePrivateServiceVisitorParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) AcceptPrivateServiceInvitation(ctx context.Context, secret string) (controlv1.PrivateServiceGrant, error) {
	return requestWithAccess[controlv1.PrivateServiceGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptPrivateServiceInvitation(ctx, controlv1.AcceptPrivateServiceInvitationJSONRequestBody{Secret: secret}, e...)
	})
}

func (c *Client) ListPrivateServiceInvitations(ctx context.Context, service string) ([]controlv1.PrivateServiceInvitation, error) {
	all := make([]controlv1.PrivateServiceInvitation, 0)
	after := ""
	for {
		page, err := requestWithAccess[controlv1.PrivateServiceInvitationPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListPrivateServiceInvitations(ctx, service, &controlv1.ListPrivateServiceInvitationsParams{Cursor: cursorString(after)}, e...)
		})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(page.Invitations))
		for _, row := range page.Invitations {
			if row.PrivateServiceId != service || row.Secret != nil {
				return nil, invalidServiceAccessPage()
			}
			ids = append(ids, row.Id)
		}
		if page.Invitations == nil || !validServiceAccessPage(ids, after, page.NextCursor, opaqueid.PrivateServiceInvitationPrefix) {
			return nil, invalidServiceAccessPage()
		}
		all = append(all, page.Invitations...)
		if page.NextCursor == nil {
			return all, nil
		}
		after = *page.NextCursor
	}
}

func (c *Client) RevokePrivateServiceInvitation(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePrivateServiceInvitation(ctx, service, id, e...)
	})
	return err
}

func (c *Client) ListPrivateServiceGrants(ctx context.Context, service string) ([]controlv1.PrivateServiceGrant, error) {
	all := make([]controlv1.PrivateServiceGrant, 0)
	after := ""
	for {
		page, err := requestWithAccess[controlv1.PrivateServiceGrantPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListPrivateServiceGrants(ctx, service, &controlv1.ListPrivateServiceGrantsParams{Cursor: cursorString(after)}, e...)
		})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(page.Grants))
		for _, row := range page.Grants {
			if row.PrivateServiceId != service || !row.Kind.Valid() {
				return nil, invalidServiceAccessPage()
			}
			ids = append(ids, row.Id)
		}
		if page.Grants == nil || !validServiceAccessPage(ids, after, page.NextCursor, opaqueid.PrivateServiceGrantPrefix) {
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

func (c *Client) RevokePrivateServiceGrant(ctx context.Context, service, id string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePrivateServiceGrant(ctx, service, id, e...)
	})
	return err
}
