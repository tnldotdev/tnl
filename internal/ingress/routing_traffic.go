package ingress

import (
	"errors"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func routingTraffic(t ingressv1.IngressTrafficLimits) (TrafficLimits, error) {
	l := TrafficLimits{Connections: t.Connections, Rate: t.Rate, RatePer: time.Duration(t.RatePerNs), Burst: t.Burst, UploadBytes: t.UploadBytes, DownloadBytes: t.DownloadBytes}
	for _, p := range []struct {
		from *int64
		to   *int64
	}{
		{t.TotalConnections, &l.TotalConnections}, {t.TotalUploadBytes, &l.TotalUploadBytes}, {t.TotalDownloadBytes, &l.TotalDownloadBytes},
	} {
		if p.from != nil {
			if *p.from <= 0 {
				return l, errors.New("ingress: invalid traffic total")
			}
			*p.to = *p.from
		}
	}
	if !l.Valid() || t.RatePerNs == 0 {
		return l, errors.New("ingress: invalid traffic projection")
	}
	return l, nil
}
