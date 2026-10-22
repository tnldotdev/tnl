package authority

import (
	"context"
	"net/http"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (c *Client) CreateCompanyLoginIntent(ctx context.Context, team string) (authorityv1.CompanyLoginIntent, error) {
	return request[authorityv1.CompanyLoginIntent](ctx, c, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateCompanyLoginIntent(ctx, authorityv1.CreateCompanyLoginIntentJSONRequestBody{TeamId: team}, e...)
	})
}

func (c *Client) ResolveCompanyLoginIntent(ctx context.Context, id, binding string) (authorityv1.CompanyLoginIntent, error) {
	return request[authorityv1.CompanyLoginIntent](ctx, c, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ResolveCompanyLoginIntent(ctx, id, authorityv1.CompanyIntentCredential{BindingToken: binding}, e...)
	})
}
