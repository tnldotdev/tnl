package config

import (
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/applicationlimits"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

// MaxConfigInteger is the largest integer shared exactly by Go and JavaScript.
const MaxConfigInteger = 1<<53 - 1

// ResolveWorkLimits selects the HTTP request or TCP connection budget without
// applying publisher defaults. traffic limits remain in Limits.Traffic.
func ResolveWorkLimits(limits *Limits, protocol string) (applicationlimits.Limits, error) {
	if !ValidProtocol(protocol) {
		return applicationlimits.Limits{}, errors.New("unsupported service protocol")
	}
	if err := validateLimits(limits, nil, ""); err != nil {
		return applicationlimits.Limits{}, err
	}
	result := applicationlimits.Limits{}
	if limits == nil {
		return result, nil
	}
	selected := limits.HTTP
	if protocol != "http" {
		selected = limits.TCP
	}
	if selected == nil {
		return result, nil
	}
	if selected.Total != nil {
		result.Requests = *selected.Total
	}
	if selected.Concurrency != nil {
		result.Concurrency = *selected.Concurrency
	}
	if selected.Rate != nil {
		result.RateRequests, result.RatePer = *selected.Rate.Count, selected.Rate.Per.Value()
		if selected.Rate.Burst != nil {
			result.RateBurst = *selected.Rate.Burst
		}
	}
	return result, nil
}

// ResolveTrafficSelection sends only configured values to control. control
// applies its defaults and ceilings when it creates the publish run.
func ResolveTrafficSelection(limits *Limits) (*trafficlimits.Selection, error) {
	if err := validateLimits(limits, nil, ""); err != nil {
		return nil, err
	}
	if limits == nil || limits.Traffic == nil {
		return nil, nil
	}
	return trafficSelection(limits.Traffic), nil
}

func trafficSelection(t *TrafficLimits) *trafficlimits.Selection {
	s := &trafficlimits.Selection{
		Connections: t.Connections, Rate: t.Rate, Burst: t.Burst,
		UploadBytes: t.UploadBytes, DownloadBytes: t.DownloadBytes,
		TotalConnections: t.TotalConnections, TotalUploadBytes: t.TotalUploadBytes,
		TotalDownloadBytes: t.TotalDownloadBytes,
	}
	if t.RatePer != nil {
		period := t.RatePer.Value().String()
		s.RatePer = &period
	}
	return s
}

func tunnelLimits(tunnel *Tunnel) *Limits {
	if tunnel == nil {
		return nil
	}
	return tunnel.Limits
}

// MergeLimits merges each protocol independently. a service rate may override
// one field while inheriting the remaining fields from project defaults.
func MergeLimits(base, override *Limits) *Limits {
	if base == nil && override == nil {
		return nil
	}
	result := &Limits{}
	if base != nil {
		*result = *base
	}
	if override == nil {
		override = &Limits{}
	}
	result.HTTP = mergeWorkLimits(result.HTTP, override.HTTP)
	result.TCP = mergeWorkLimits(result.TCP, override.TCP)
	result.Traffic = mergeTrafficLimits(result.Traffic, override.Traffic)
	return result
}

func mergeWorkLimits(base, override *WorkLimits) *WorkLimits {
	if base == nil && override == nil {
		return nil
	}
	r := &WorkLimits{}
	if base != nil {
		*r = *base
	}
	if override != nil {
		if override.Total != nil {
			r.Total = override.Total
		}
		if override.Concurrency != nil {
			r.Concurrency = override.Concurrency
		}
	}
	if r.Rate != nil {
		rate := *r.Rate
		r.Rate = &rate
	}
	if override != nil && override.Rate != nil {
		if r.Rate == nil {
			r.Rate = &Rate{}
		}
		if override.Rate.Count != nil {
			r.Rate.Count = override.Rate.Count
		}
		if override.Rate.Per != nil {
			r.Rate.Per = override.Rate.Per
		}
		if override.Rate.Burst != nil {
			r.Rate.Burst = override.Rate.Burst
		}
	}
	return r
}

func mergeTrafficLimits(base, override *TrafficLimits) *TrafficLimits {
	if base == nil && override == nil {
		return nil
	}
	r := &TrafficLimits{}
	if base != nil {
		*r = *base
	}
	if override != nil {
		for _, pair := range []struct{ from, to **int }{{&override.Connections, &r.Connections}, {&override.Rate, &r.Rate}, {&override.Burst, &r.Burst}} {
			if *pair.from != nil {
				*pair.to = *pair.from
			}
		}
		if override.RatePer != nil {
			r.RatePer = override.RatePer
		}
		for _, pair := range []struct{ from, to **int64 }{
			{&override.UploadBytes, &r.UploadBytes}, {&override.DownloadBytes, &r.DownloadBytes},
			{&override.TotalConnections, &r.TotalConnections}, {&override.TotalUploadBytes, &r.TotalUploadBytes},
			{&override.TotalDownloadBytes, &r.TotalDownloadBytes},
		} {
			if *pair.from != nil {
				*pair.to = *pair.from
			}
		}
	}
	return r
}

func validateLimits(value, base *Limits, protocol string) error {
	if value != nil && protocol != "" {
		if protocol == "http" && value.TCP != nil || protocol != "http" && value.HTTP != nil {
			return errors.New("public_url.limits protocol block does not match service protocol")
		}
	}
	merged := MergeLimits(base, value)
	if merged == nil {
		return nil
	}
	for _, block := range []struct {
		name   string
		limits *WorkLimits
	}{{"http", merged.HTTP}, {"tcp", merged.TCP}} {
		name, limits := block.name, block.limits
		if limits == nil {
			continue
		}
		for _, n := range []*int{limits.Total, limits.Concurrency} {
			if n != nil && (*n < 1 || *n > MaxConfigInteger) {
				return fmt.Errorf("public_url.limits.%s values must be positive safe integers", name)
			}
		}
		if rate := limits.Rate; rate != nil {
			if rate.Count == nil || rate.Per == nil {
				return fmt.Errorf("public_url.limits.%s.rate requires count and per", name)
			}
			if *rate.Count < 1 || *rate.Count > MaxConfigInteger || rate.Per.Value() <= 0 || rate.Burst != nil && (*rate.Burst < 1 || *rate.Burst > MaxConfigInteger) {
				return fmt.Errorf("public_url.limits.%s.rate values must be positive and within bounds", name)
			}
		}
	}
	if traffic := merged.Traffic; traffic != nil {
		for _, n := range []*int{traffic.Connections, traffic.Rate, traffic.Burst} {
			if n != nil && (*n < 1 || *n > MaxConfigInteger) {
				return errors.New("public_url.limits.traffic connection and rate values must be positive safe integers")
			}
		}
		for _, n := range []*int64{traffic.UploadBytes, traffic.DownloadBytes, traffic.TotalConnections, traffic.TotalUploadBytes, traffic.TotalDownloadBytes} {
			if n != nil && (*n < 1 || *n > MaxConfigInteger) {
				return errors.New("public_url.limits.traffic byte and total values must be positive safe integers")
			}
		}
		if traffic.RatePer != nil && (traffic.RatePer.Value() < 1e6 || traffic.RatePer.Value() > 24*60*60*1e9) {
			return errors.New("public_url.limits.traffic.rate_per must be between 1ms and 24h")
		}
		if err := trafficSelection(traffic).Validate(); err != nil {
			return fmt.Errorf("public_url.limits.traffic: %w", err)
		}
	}
	return nil
}
