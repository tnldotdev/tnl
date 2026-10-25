package invocation

import (
	"context"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// publicationVisitors exposes explicit visitor preparation and publish-run-token
// browser and feedback operations.
// saved URL operations and signed run creation remain owned by Native.
type publicationVisitors interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
	IssueVisitorToken(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error)
	RedeemBrowserHandoff(context.Context, string, uint64, string, string, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, credentials.PublishRunToken) (controlv1.ShareRedemption, error)
	CreatePublishRunPreview(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.Preview, error)
	CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error)
	GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.PublishRunToken) (controlv1.FeedbackEvent, error)
}

type publicationControl struct {
	publisher.PublicURLControlClient
	publicationVisitors
}

var _ publisher.PublicURLControlClient = publicationControl{}
var _ publicationVisitors = (*clientcontrol.Client)(nil)

func nativePublicationControl(native *publisheridentity.Native, control *clientcontrol.Client) publicationControl {
	return publicationControl{PublicURLControlClient: native, publicationVisitors: control}
}

// guestPublicationControl limits cleanup to the trial session's assigned URL.
type guestPublicationControl struct {
	publicationControl
	assigned  controlv1.PublicURL
	bootstrap *clientcontrol.Client
}

func (c guestPublicationControl) DeletePublicURL(ctx context.Context, id string) error {
	if id != c.assigned.Id {
		return publisheridentity.ErrScope
	}
	return c.bootstrap.DeletePublicURL(ctx, id)
}
