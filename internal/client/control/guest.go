package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) AllocateGuestDemoService(ctx context.Context, key string, body controlv1.AllocateGuestDemoServiceRequest) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AllocateGuestDemoService(ctx, &controlv1.AllocateGuestDemoServiceParams{IdempotencyKey: key}, body, editors...)
	})
}

// the bootstrap response uses the defining ordinary enrollment shape. only the
// trial credential authorizes enrollment; service publication uses its own key.
func (c *Client) EnrollGuestPublisher(ctx context.Context, service string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	return requestWithAccess[authorityv1.PublisherEnrollmentResult](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.EnrollGuestPublisher(ctx, controlv1.EnrollGuestPublisherRequest{
			ServiceId: service, PublicKey: base64.RawURLEncoding.EncodeToString(public),
		}, editors...)
	})
}
