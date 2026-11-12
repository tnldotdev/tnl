package public

import (
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func environmentHTTPFromAPI(input controlv1.EnvironmentServiceHTTP) (*controlstate.EnvironmentServiceHTTP, error) {
	result := &controlstate.EnvironmentServiceHTTP{}
	if a := input.Access; a != nil {
		result.Access = &config.Access{}
		if a.Mode != nil {
			result.Access.Mode = string(*a.Mode)
		}
		if a.Ip != nil {
			result.Access.IP = *a.Ip
		}
	}
	if l := input.Limits; l != nil {
		result.Limits = &config.WorkLimits{Total: l.Total, Concurrency: l.Concurrency}
		if r := l.Rate; r != nil {
			period, err := time.ParseDuration(r.Per)
			if err != nil || period <= 0 {
				return nil, controlstate.ErrEnvironmentInvalid
			}
			result.Limits.Rate = &config.Rate{Count: new(r.Count), Per: new(config.Duration(period)), Burst: r.Burst}
		}
	}
	return result, nil
}

func environmentHTTPResponse(input *controlstate.EnvironmentServiceHTTP) *controlv1.EnvironmentServiceHTTP {
	if input == nil {
		return nil
	}
	result := &controlv1.EnvironmentServiceHTTP{}
	if a := input.Access; a != nil {
		result.Access = &controlv1.ProjectPublicAccess{Mode: new(controlv1.VisitorAccessMode(a.Mode))}
		if a.IP != nil {
			result.Access.Ip = new(a.IP)
		}
	}
	if l := input.Limits; l != nil {
		result.Limits = &controlv1.ProjectHTTPApplicationLimits{Total: l.Total, Concurrency: l.Concurrency}
		if r := l.Rate; r != nil {
			result.Limits.Rate = &controlv1.ProjectApplicationRate{Count: *r.Count, Per: time.Duration(*r.Per).String(), Burst: r.Burst}
		}
	}
	return result
}
