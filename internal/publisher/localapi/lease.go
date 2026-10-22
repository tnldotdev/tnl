package localapi

import (
	"context"
	"errors"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

// LeaseClient is owned by one CLI invocation. Resolve rereads private discovery
// on every renewal, so a replacement owner receives a fresh scoped request.
type LeaseClient struct {
	Resolve      func(context.Context) (publisherprotocol.Endpoint, error)
	Request      publisherprotocol.Lease
	endpoint     publisherprotocol.Endpoint
	registration publisherprotocol.Registration
}

func (c *LeaseClient) Renew(ctx context.Context) (publisherprotocol.Endpoint, publisherprotocol.Registration, error) {
	endpoint, err := c.Resolve(ctx)
	if err != nil {
		return endpoint, publisherprotocol.Registration{}, err
	}
	if c.registration.RegistrationID != "" && c.endpoint.OwnerId == endpoint.OwnerId {
		err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/renew", c.registration, nil)
		if err == nil {
			return endpoint, c.registration, nil
		}
		var response *publisherprotocol.ResponseError
		if !errors.Is(err, publisherprotocol.ErrUnauthorized) && !(errors.As(err, &response) && response.Status == 409) {
			return endpoint, c.registration, err
		}
	}
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/leases", c.Request, &registration); err != nil {
		return endpoint, registration, err
	}
	if registration.Version != 1 || registration.Owner != c.Request.Owner || registration.RegistrationID == "" {
		return endpoint, publisherprotocol.Registration{}, errors.New("local publisher returned an invalid lease")
	}
	c.endpoint, c.registration = endpoint, registration
	return endpoint, registration, nil
}

func (c *LeaseClient) Close(ctx context.Context) error {
	if c.registration.RegistrationID == "" {
		return nil
	}
	err := publisherprotocol.Call(ctx, c.endpoint, "POST", "/v1/unregister", c.registration, nil)
	c.registration = publisherprotocol.Registration{}
	return err
}
