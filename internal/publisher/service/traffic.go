package service

import (
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// serviceTraffic validates an immutable control approval without applying local
// defaults or ceilings. ingress owns its counters; connector capacity is separate.
func serviceTraffic(approved controlv1.TrafficLimits) (trafficlimits.Limits, error) {
	limits := trafficlimits.Limits{
		Connections: approved.Connections, Rate: approved.Rate, RatePer: time.Duration(approved.RatePerNs), Burst: approved.Burst,
		UploadBytes: approved.UploadBytes, DownloadBytes: approved.DownloadBytes,
	}
	for _, pair := range []struct {
		from *int64
		to   *int64
	}{
		{approved.TotalConnections, &limits.TotalConnections},
		{approved.TotalUploadBytes, &limits.TotalUploadBytes},
		{approved.TotalDownloadBytes, &limits.TotalDownloadBytes},
	} {
		if pair.from != nil {
			if *pair.from <= 0 {
				return trafficlimits.Limits{}, ErrPrivateStream
			}
			*pair.to = *pair.from
		}
	}
	if approved.RatePerNs == 0 || !limits.Valid() {
		return trafficlimits.Limits{}, ErrPrivateStream
	}
	return limits, nil
}

func cloneTrafficApproval(approved controlv1.TrafficLimits) controlv1.TrafficLimits {
	for _, value := range []**int64{&approved.TotalConnections, &approved.TotalUploadBytes, &approved.TotalDownloadBytes} {
		if *value != nil {
			*value = new(**value)
		}
	}
	return approved
}
