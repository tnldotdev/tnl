package publisherauth

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// RunControl keeps publisher access separate from the human control session.
// installed owners cannot edit public URL settings through this adapter.
type RunControl struct {
	*controlclient.Client
	Owner *Owner
}

func (c *RunControl) CreatePublishRun(ctx context.Context, publicURLID, key string) (controlv1.PublishRunSetup, error) {
	return c.Owner.CreateRun(ctx, publicURLID, key)
}

func (c *RunControl) CreatePublishRunWithTraffic(ctx context.Context, publicURLID, key string, traffic trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	return c.Owner.CreateRun(ctx, publicURLID, key, traffic)
}

func (c *RunControl) GetPublicURLByHostname(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	return c.Owner.BoundURL(ctx, teamID, hostname)
}

func (c *RunControl) CreatePublicURL(ctx context.Context, body controlv1.CreatePublicURLRequest, key string) (controlv1.PublicURL, error) {
	if c.Owner.human == nil {
		if c.Owner.guestControl != nil {
			return c.Owner.guestControl.CreatePublicURL(ctx, body, key)
		}
		return controlv1.PublicURL{}, errors.New("installed publisher cannot create public URLs")
	}
	return c.Owner.human.Control.CreatePublicURL(ctx, body, key)
}

func (c *RunControl) UpdatePublicURL(ctx context.Context, id string, body controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	if c.Owner.human == nil {
		if c.Owner.guestControl != nil {
			return c.Owner.guestControl.UpdatePublicURL(ctx, id, body)
		}
		return controlv1.PublicURL{}, errors.New("installed publisher cannot change public URL settings")
	}
	return c.Owner.human.Control.UpdatePublicURL(ctx, id, body)
}

func (c *RunControl) DeletePublicURL(ctx context.Context, id string) error {
	if c.Owner.human == nil {
		if c.Owner.guestControl != nil {
			return c.Owner.guestControl.DeletePublicURL(ctx, id)
		}
		return errors.New("installed publisher cannot delete public URLs")
	}
	return c.Owner.human.Control.DeletePublicURL(ctx, id)
}
