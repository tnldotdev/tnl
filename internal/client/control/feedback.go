package control

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	return request[controlv1.Preview](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateServiceRunPreview(ctx, service, run, controlv1.ServiceRunPreviewRequest{RunNumber: number}, editors...)
	})
}
func (c *Client) AuthorizeReviewerFeedback(ctx context.Context, service, run string, body controlv1.AuthorizeReviewerFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error) {
	return request[controlv1.FeedbackAuthorization](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeReviewerFeedback(ctx, service, run, body, editors...)
	})
}
func (c *Client) AuthorizeImplementerFeedback(ctx context.Context, body controlv1.AuthorizeImplementerFeedbackRequest) (controlv1.FeedbackAuthorization, error) {
	return requestWithAccess[controlv1.FeedbackAuthorization](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeImplementerFeedback(ctx, body, editors...)
	})
}
