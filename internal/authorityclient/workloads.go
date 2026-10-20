package authorityclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (c *Client) ExchangeGitHubWorkload(ctx context.Context, body authorityv1.GitHubWorkloadExchange) (authorityv1.WorkloadSession, error) {
	return requestWithToken[authorityv1.WorkloadSession](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeGitHubWorkload(ctx, body, editors...)
	})
}
func (c *Client) RenewWorkloadSession(ctx context.Context, id, credential string) (authorityv1.WorkloadSession, error) {
	return requestWithToken[authorityv1.WorkloadSession](ctx, c, credential, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewWorkloadSession(ctx, id, editors...)
	})
}
func (c *Client) RevokeWorkloadSession(ctx context.Context, id, credential string) error {
	_, err := requestWithToken[struct{}](ctx, c, credential, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeWorkloadSession(ctx, id, editors...)
	})
	return err
}
