package config

import (
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

// MaxConfigInteger is the largest integer shared exactly by Go and JavaScript.
const MaxConfigInteger = 1<<53 - 1

// ResolveWorkLimits converts an explicit application budget without defaults.
func ResolveWorkLimits(limits *WorkLimits) (applicationlimits.Limits, error) {
	if err := validateWorkLimits(limits); err != nil {
		return applicationlimits.Limits{}, err
	}
	result := applicationlimits.Limits{}
	if limits == nil {
		return result, nil
	}
	if limits.Total != nil {
		result.Requests = *limits.Total
	}
	if limits.Concurrency != nil {
		result.Concurrency = *limits.Concurrency
	}
	if limits.Rate != nil {
		result.RateRequests, result.RatePer = *limits.Rate.Count, limits.Rate.Per.Value()
		if limits.Rate.Burst != nil {
			result.RateBurst = *limits.Rate.Burst
		}
	}
	return result, nil
}

// ResolveTrafficSelection sends configured values only. control applies its
// defaults and ceilings when it creates the service run.
func ResolveTrafficSelection(traffic *TrafficLimits) (*trafficlimits.Selection, error) {
	if traffic == nil {
		return nil, nil
	}
	for _, n := range []*int{traffic.Connections, traffic.Rate, traffic.Burst} {
		if n != nil && (*n < 1 || *n > MaxConfigInteger) {
			return nil, errors.New("connection and rate values must be positive safe integers")
		}
	}
	for _, n := range []*int64{traffic.UploadBytes, traffic.DownloadBytes, traffic.TotalConnections, traffic.TotalUploadBytes, traffic.TotalDownloadBytes} {
		if n != nil && (*n < 1 || *n > MaxConfigInteger) {
			return nil, errors.New("byte and total values must be positive safe integers")
		}
	}
	if traffic.RatePer != nil && (traffic.RatePer.Value() < 1e6 || traffic.RatePer.Value() > 24*60*60*1e9) {
		return nil, errors.New("rate_per must be between 1ms and 24h")
	}
	selection := &trafficlimits.Selection{
		Connections: traffic.Connections, Rate: traffic.Rate, Burst: traffic.Burst,
		UploadBytes: traffic.UploadBytes, DownloadBytes: traffic.DownloadBytes,
		TotalConnections: traffic.TotalConnections, TotalUploadBytes: traffic.TotalUploadBytes,
		TotalDownloadBytes: traffic.TotalDownloadBytes,
	}
	if traffic.RatePer != nil {
		period := traffic.RatePer.Value().String()
		selection.RatePer = &period
	}
	if err := selection.Validate(); err != nil {
		return nil, fmt.Errorf("traffic: %w", err)
	}
	return selection, nil
}

func validateWorkLimits(limits *WorkLimits) error {
	if limits == nil {
		return nil
	}
	for _, n := range []*int{limits.Total, limits.Concurrency} {
		if n != nil && (*n < 1 || *n > MaxConfigInteger) {
			return errors.New("http.limits values must be positive safe integers")
		}
	}
	if rate := limits.Rate; rate != nil {
		if rate.Count == nil || rate.Per == nil {
			return errors.New("http.limits.rate requires count and per")
		}
		if *rate.Count < 1 || *rate.Count > MaxConfigInteger || rate.Per.Value() <= 0 || rate.Burst != nil && (*rate.Burst < 1 || *rate.Burst > MaxConfigInteger) {
			return errors.New("http.limits.rate values must be positive and within bounds")
		}
	}
	return nil
}
