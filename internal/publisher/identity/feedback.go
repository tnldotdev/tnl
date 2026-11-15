package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceFeedbackControl interface {
	CreateServiceRunPreview(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error)
	CreateFeedbackReport(context.Context, string, string, string, controlv1.CreateFeedbackReportRequest, credentials.ServiceRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, string, controlv1.PreviewPageFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackThreadPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.ServiceRunToken) (controlv1.FeedbackEvent, error)
	GetReviewerFeedbackThread(context.Context, string, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.ServiceRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.ServiceRunToken) (controlv1.FeedbackEventPage, error)
}

func (n *Native) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.Preview{}, err
	}
	return control.CreateServiceRunPreview(ctx, service, run, number, token)
}

func (n *Native) CreateFeedbackReport(ctx context.Context, service, run, key string, body controlv1.CreateFeedbackReportRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThread, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackThread{}, err
	}
	return control.CreateFeedbackReport(ctx, service, run, key, body, token)
}

func (n *Native) ListPreviewPageFeedback(ctx context.Context, service, run string, body controlv1.PreviewPageFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThreadPage, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackThreadPage{}, err
	}
	return control.ListPreviewPageFeedback(ctx, service, run, body, token)
}

func (n *Native) AppendReviewerFeedbackEvent(ctx context.Context, service, run, feedback, key string, body controlv1.AppendReviewerFeedbackEventRequest, token credentials.ServiceRunToken) (controlv1.FeedbackEvent, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackEvent{}, err
	}
	return control.AppendReviewerFeedbackEvent(ctx, service, run, feedback, key, body, token)
}

func (n *Native) GetReviewerFeedbackThread(ctx context.Context, service, run, feedback string, body controlv1.ReviewerFeedbackReadRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThread, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackThread{}, err
	}
	return control.GetReviewerFeedbackThread(ctx, service, run, feedback, body, token)
}

func (n *Native) ListReviewerFeedbackEvents(ctx context.Context, service, run, feedback string, body controlv1.ReviewerFeedbackReadRequest, token credentials.ServiceRunToken) (controlv1.FeedbackEventPage, error) {
	control, err := n.serviceHTTP(service)
	if err != nil {
		return controlv1.FeedbackEventPage{}, err
	}
	return control.ListReviewerFeedbackEvents(ctx, service, run, feedback, body, token)
}
