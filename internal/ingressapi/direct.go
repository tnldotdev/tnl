package ingressapi

import "time"

type DirectConfig struct {
	Store               Store
	LeaseDuration       time.Duration
	RoutingPollInterval time.Duration
	Now                 func() time.Time
	Report              func(error)
}

// DirectClient executes private ingress operations in-process for standalone.
type DirectClient struct{ *service }

func NewDirectClient(config DirectConfig) (*DirectClient, error) {
	service, err := newService(config)
	if err != nil {
		return nil, err
	}
	return &DirectClient{service: service}, nil
}
