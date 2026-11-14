package config

import (
	"errors"
	"slices"
)

// ResolvePublicURLHTTP selects request policy without selecting reachability or
// a resource identity. legacy fields and http fields cannot both own a setting.
func ResolvePublicURLHTTP(defaults, binding *Tunnel, value *HTTPService) (*HTTPService, error) {
	result := &HTTPService{}
	if value != nil {
		*result = *value
	}
	if binding != nil && value != nil {
		if binding.Access != nil && value.Access != nil {
			return nil, errors.New("set HTTP access in http.access, not also in public_url.access")
		}
		if binding.Limits != nil && binding.Limits.HTTP != nil && value.Limits != nil {
			return nil, errors.New("set HTTP request limits in http.limits, not also in public_url.limits.http")
		}
	}
	var access *Access
	var limits *Limits
	for _, source := range []*Tunnel{defaults, binding} {
		if source == nil {
			continue
		}
		if source.Access != nil {
			access = source.Access
		}
		limits = MergeLimits(limits, source.Limits)
	}
	if result.Access == nil {
		result.Access = access
	}
	if result.Access != nil {
		access := *result.Access
		access.IP = slices.Clone(access.IP)
		result.Access = &access
	}
	limits = MergeLimits(limits, &Limits{HTTP: result.Limits})
	result.Limits = limits.HTTP
	if err := ValidatePublicURLHTTP(result, false); err != nil {
		return nil, err
	}
	return result, nil
}
