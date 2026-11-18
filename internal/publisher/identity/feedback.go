//go:build !js || !wasm

package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceFeedbackControl interface {
	CreateServiceRunPreview(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error)
	AuthorizeReviewerFeedback(context.Context, string, string, controlv1.AuthorizeReviewerFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error)
}

func (n *Native) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.Preview{}, err
	}
	return control.CreateServiceRunPreview(ctx, service, run, number, token)
}
func (n *Native) AuthorizeReviewerFeedback(ctx context.Context, service, run string, body controlv1.AuthorizeReviewerFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackAuthorization{}, err
	}
	return control.AuthorizeReviewerFeedback(ctx, service, run, body, token)
}
