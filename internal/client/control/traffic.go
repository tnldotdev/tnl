package control

import (
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// TrafficSelection converts explicit choices without resolving defaults or
// retaining caller-owned pointers.
func TrafficSelection(selection *trafficlimits.Selection) (*controlv1.TrafficSelection, error) {
	if selection == nil {
		return nil, nil
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	s := selection.Clone()
	return &controlv1.TrafficSelection{
		Connections: s.Connections, Rate: s.Rate, RatePer: s.RatePer, Burst: s.Burst,
		UploadBytes: s.UploadBytes, DownloadBytes: s.DownloadBytes,
		TotalConnections: s.TotalConnections, TotalUploadBytes: s.TotalUploadBytes, TotalDownloadBytes: s.TotalDownloadBytes,
	}, nil
}
