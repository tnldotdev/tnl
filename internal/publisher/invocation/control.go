package invocation

import (
	"context"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// publicationVisitors exposes explicit visitor preparation and publish-run-token
// browser and feedback operations.
// saved URL operations and signed run creation remain owned by Native.
type publicationVisitors interface {
	publisher.VisitorControlClient
	publisher.BrowserControlClient
	httpaccess.ShareClient
	publisher.PreviewClient
	publisher.FeedbackClient
}

var _ publisher.PublicURLControlClient = guestPublicationControl{}
var _ publicationVisitors = (*clientcontrol.Client)(nil)

func configureNativePublication(cfg *publisher.Config, native *publisheridentity.Native, visitors publicationVisitors) {
	cfg.Identity, cfg.Audit, cfg.VisitorControl = native, native, visitors
	cfg.BrowserControl = visitors
	cfg.Shares, cfg.Previews, cfg.FeedbackControl = visitors, visitors, visitors
	// serving a signed grant never inherits management authority from a session.
	cfg.Management, cfg.AccessManagement = nil, nil
}

// guestPublicationControl limits cleanup to the trial session's assigned URL.
type guestPublicationControl struct {
	publisher.PublicURLControlClient
	assigned  controlv1.PublicURL
	bootstrap *clientcontrol.Client
}

func (c guestPublicationControl) DeletePublicURL(ctx context.Context, id string) error {
	if id != c.assigned.Id {
		return publisheridentity.ErrScope
	}
	return c.bootstrap.DeletePublicURL(ctx, id)
}
