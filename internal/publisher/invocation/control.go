package invocation

import (
	"context"
	"slices"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publicationVisitors exposes only publish-run-token visitor and feedback calls.
// saved URL operations and signed run creation remain owned by Native.
type publicationVisitors interface {
	AuthorizeHTTPVisitor(context.Context, string, controlv1.HTTPVisitorRequest, credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error)
	RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	EnableShareAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
	GetPublishRunShareState(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunShareState, error)
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
var _ publicationVisitors = (*controlclient.Client)(nil)

func nativePublicationControl(native *nativeauth.Native, control *controlclient.Client) publicationControl {
	return publicationControl{PublicURLControlClient: native, publicationVisitors: control}
}

// guestPublicationControl gives the engine the demo URL already assigned by the
// trial session. it cannot create another URL or delete a different URL, and
// Native still owns every signed run operation.
type guestPublicationControl struct {
	publicationControl
	assigned  controlv1.PublicURL
	bootstrap *controlclient.Client
}

func (c guestPublicationControl) CreatePublicURL(_ context.Context, body controlv1.CreatePublicURLRequest, _ string) (controlv1.PublicURL, error) {
	protocol := controlv1.Http
	if body.ServiceProtocol != nil {
		protocol = *body.ServiceProtocol
	}
	prefixes := []string{}
	if body.AllowedIpPrefixes != nil {
		prefixes = *body.AllowedIpPrefixes
	}
	assigned := []string{}
	if c.assigned.AllowedIpPrefixes != nil {
		assigned = *c.assigned.AllowedIpPrefixes
	}
	if body.Purpose != controlv1.Demo || protocol != controlv1.Http || body.Ephemeral == nil || !*body.Ephemeral || body.TeamId != c.assigned.TeamId || body.DomainId != c.assigned.DomainId || body.CanonicalHostname != c.assigned.CanonicalHostname || body.PublicUrlScope != c.assigned.PublicUrlScope || body.Target != c.assigned.Target || body.MembershipId == nil || c.assigned.MembershipId == nil || *body.MembershipId != *c.assigned.MembershipId || !slices.Equal(prefixes, assigned) {
		return controlv1.PublicURL{}, nativeauth.ErrScope
	}
	return c.assigned, nil
}

func (c guestPublicationControl) DeletePublicURL(ctx context.Context, id string) error {
	if id != c.assigned.Id {
		return nativeauth.ErrScope
	}
	return c.bootstrap.DeletePublicURL(ctx, id)
}
