package adhoc

import (
	"context"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type scopedControl struct {
	*controlclient.Client
	route   controlv1.PublicURL
	owner   *publisherauth.Owner
	grantID string
}

var _ publisher.PublicURLControlClient = (*scopedControl)(nil)

func (c *scopedControl) GetPublicURLByHostname(_ context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	if c.route.TeamId != teamID || c.route.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, controlclient.ErrStatusConflict
	}
	return c.route, nil
}

func (c *scopedControl) CreatePublishRun(ctx context.Context, publicURLID, key string) (controlv1.PublishRunSetup, error) {
	if publicURLID != c.route.Id {
		return controlv1.PublishRunSetup{}, controlclient.ErrStatusConflict
	}
	return c.owner.CreateNamespaceRun(ctx, publicURLID, c.grantID, key)
}

func (c *scopedControl) CreatePublishRunWithTraffic(ctx context.Context, publicURLID, key string, traffic trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	if publicURLID != c.route.Id {
		return controlv1.PublishRunSetup{}, controlclient.ErrStatusConflict
	}
	return c.owner.CreateNamespaceRun(ctx, publicURLID, c.grantID, key, traffic)
}

func (c *scopedControl) CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (c *scopedControl) UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (c *scopedControl) DeletePublicURL(ctx context.Context, publicURLID string) error {
	if publicURLID != c.route.Id {
		return controlclient.ErrStatusConflict
	}
	return c.owner.DeleteNamespaceURL(ctx, c.grantID, publicURLID)
}
