package native

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrTrafficUnsupported = errors.New("publisher control client cannot select traffic limits")

// TrafficControl is optional so NativeControl's existing proof-bearing method
// keeps its exact signature. a selection is never silently discarded.
type TrafficControl interface {
	CreatePublisherRunWithTraffic(context.Context, string, string, string, string, *trafficlimits.Selection) (controlv1.PublishRunSetup, error)
}

// WithTraffic makes an independent worker selection without changing the
// original adapter or retaining caller-owned pointers.
func (n *Native) WithTraffic(selection *trafficlimits.Selection) (*Native, error) {
	if n == nil {
		return nil, ErrScope
	}
	copy := *n
	copy.private = append(copy.private[:0:0], n.private...)
	copy.route = clonePublicURL(n.route)
	copy.traffic = nil
	if selection == nil {
		return &copy, nil
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	if _, ok := n.NativeControl.(TrafficControl); !ok {
		return nil, ErrTrafficUnsupported
	}
	copy.traffic = selection.Clone()
	return &copy, nil
}
