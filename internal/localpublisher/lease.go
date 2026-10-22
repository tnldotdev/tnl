package localpublisher

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

// LeaseClient is owned by one CLI invocation. Resolve rereads private discovery
// on every renewal, so a replacement owner receives a fresh scoped request.
type LeaseClient struct {
	Resolve      func(context.Context) (privateprotocol.Endpoint, error)
	Request      privateprotocol.Lease
	endpoint     privateprotocol.Endpoint
	registration privateprotocol.Registration
}

func (c *LeaseClient) Renew(ctx context.Context) (privateprotocol.Endpoint, privateprotocol.Registration, error) {
	endpoint, err := c.Resolve(ctx)
	if err != nil {
		return endpoint, privateprotocol.Registration{}, err
	}
	if c.registration.RegistrationID != "" && c.endpoint.OwnerId == endpoint.OwnerId {
		err := privateprotocol.Call(ctx, endpoint, "POST", "/v1/renew", c.registration, nil)
		if err == nil {
			return endpoint, c.registration, nil
		}
		var response *privateprotocol.ResponseError
		if !errors.Is(err, privateprotocol.ErrUnauthorized) && !(errors.As(err, &response) && response.Status == 409) {
			return endpoint, c.registration, err
		}
	}
	var registration privateprotocol.Registration
	if err := privateprotocol.Call(ctx, endpoint, "POST", "/v1/leases", c.Request, &registration); err != nil {
		return endpoint, registration, err
	}
	if registration.Version != 1 || registration.Owner != c.Request.Owner || registration.RegistrationID == "" {
		return endpoint, privateprotocol.Registration{}, errors.New("local publisher returned an invalid lease")
	}
	c.endpoint, c.registration = endpoint, registration
	return endpoint, registration, nil
}

func (c *LeaseClient) Close(ctx context.Context) error {
	if c.registration.RegistrationID == "" {
		return nil
	}
	err := privateprotocol.Call(ctx, c.endpoint, "POST", "/v1/unregister", c.registration, nil)
	c.registration = privateprotocol.Registration{}
	return err
}
