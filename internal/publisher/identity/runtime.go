package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// RunControl preserves the existing publisher lifecycle capabilities when a
// control client is wrapped by the signing adapter. these operations use an
// explicit publish run token; team and saved-URL management are not exposed.
type RunControl interface {
	CreatePublishRunPreview(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.Preview, error)
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	GetPublishRunShareState(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunShareState, error)
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error)
	RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	AuthorizeHTTPVisitor(context.Context, string, controlv1.HTTPVisitorRequest, credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error)
	CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.PublishRunToken) (controlv1.FeedbackEvent, error)
	GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error)
}
