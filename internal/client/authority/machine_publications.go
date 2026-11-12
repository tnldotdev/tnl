package authority

import (
	"context"
	"net/http"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// machine publication proofs are explicit and never use a human control token.
func (c *Client) ExchangeMachinePublication(ctx context.Context, body authorityv1.MachinePublicationExchange) (authorityv1.MachinePublicationSession, error) {
	return requestWithToken[authorityv1.MachinePublicationSession](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeMachinePublication(ctx, body, editors...)
	})
}

func (c *Client) RefreshMachinePublication(ctx context.Context, id string, body authorityv1.MachinePublicationRefresh) (authorityv1.MachinePublicationSession, error) {
	return requestWithToken[authorityv1.MachinePublicationSession](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RefreshMachinePublication(ctx, id, body, editors...)
	})
}

func (c *Client) CleanupMachinePublication(ctx context.Context, id string, body authorityv1.MachinePublicationCleanup) error {
	_, err := requestWithToken[struct{}](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CleanupMachinePublication(ctx, id, body, editors...)
	})
	return err
}
