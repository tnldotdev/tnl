package identity

import (
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// WithTraffic makes an independent worker selection without changing the
// original adapter or retaining caller-owned pointers.
func (n *Native) WithTraffic(selection *trafficlimits.Selection) (*Native, error) {
	if n == nil {
		return nil, ErrScope
	}
	copy := *n
	copy.private = append(copy.private[:0:0], n.private...)
	copy.publicURL = clonePublicURL(n.publicURL)
	copy.traffic = nil
	if selection == nil {
		return &copy, nil
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	copy.traffic = selection.Clone()
	return &copy, nil
}

// serviceRunTraffic uses the worker's selection, or the caller's when omitted.
// two explicit selections must agree; neither is merged or resolved locally.
func serviceRunTraffic(worker *trafficlimits.Selection, requested *controlv1.TrafficSelection) (*controlv1.TrafficSelection, error) {
	selected, err := clientcontrol.TrafficSelection(worker)
	if err != nil || requested == nil {
		return selected, err
	}
	explicit := trafficlimits.Selection{
		Connections: requested.Connections, Rate: requested.Rate, RatePer: requested.RatePer, Burst: requested.Burst,
		UploadBytes: requested.UploadBytes, DownloadBytes: requested.DownloadBytes,
		TotalConnections: requested.TotalConnections, TotalUploadBytes: requested.TotalUploadBytes, TotalDownloadBytes: requested.TotalDownloadBytes,
	}
	if err := explicit.Validate(); err != nil {
		return nil, err
	}
	if worker == nil {
		return clientcontrol.TrafficSelection(&explicit)
	}
	if !sameTrafficSelection(*worker, explicit) {
		return nil, ErrScope
	}
	return selected, nil
}

// sameTrafficSelection compares validated explicit choices, not resolved limits.
func sameTrafficSelection(a, b trafficlimits.Selection) bool {
	if !sameTrafficValue(a.Connections, b.Connections) || !sameTrafficValue(a.Rate, b.Rate) || !sameTrafficValue(a.Burst, b.Burst) ||
		!sameTrafficValue(a.UploadBytes, b.UploadBytes) || !sameTrafficValue(a.DownloadBytes, b.DownloadBytes) ||
		!sameTrafficValue(a.TotalConnections, b.TotalConnections) || !sameTrafficValue(a.TotalUploadBytes, b.TotalUploadBytes) ||
		!sameTrafficValue(a.TotalDownloadBytes, b.TotalDownloadBytes) {
		return false
	}
	if a.RatePer == nil || b.RatePer == nil {
		return a.RatePer == b.RatePer
	}
	period, _ := time.ParseDuration(*a.RatePer)
	other, _ := time.ParseDuration(*b.RatePer)
	return period == other
}

func sameTrafficValue[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
