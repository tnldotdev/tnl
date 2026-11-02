package workload

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) VisitorPermission(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	if !r.ExpiresAt.After(time.Now()) || !r.LeaseExpiresAt.After(time.Now()) || !slices.Contains(r.ServiceIds, service) {
		return controlv1.VisitorTokenResponse{}, ErrSessionExpired
	}
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: r.Credential})
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return c.control.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service}, Source: source})
}
