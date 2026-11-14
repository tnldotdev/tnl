package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ReportHTTPProtectionRejections(ctx context.Context, body controlv1.ReportHTTPProtectionRejectionsRequest, token string) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReportHTTPProtectionRejections(ctx, body, editors...)
	})
	return err
}

func (c *Client) RedeemHTTPChallenge(ctx context.Context, body controlv1.RedeemHTTPChallengeRequest, token string) (controlv1.HTTPChallengeClearance, error) {
	return request[controlv1.HTTPChallengeClearance](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemHTTPChallenge(ctx, body, editors...)
	})
}
