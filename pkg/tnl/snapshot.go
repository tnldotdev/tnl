package tnl

import controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"

// snapshots copy every optional field, including nested HTTP limits and trust.
// callers cannot mutate the tunnel or another caller's snapshot through pointers.
func cloneService(service controlv1.Service) controlv1.Service {
	service.DomainId = clonePointer(service.DomainId)
	service.Endpoint = clonePointer(service.Endpoint)
	service.ExpiresAt = clonePointer(service.ExpiresAt)
	service.KubernetesAuth = clonePointer(service.KubernetesAuth)
	service.RunNumber = clonePointer(service.RunNumber)
	service.ServiceRunId = clonePointer(service.ServiceRunId)
	service.Source = clonePointer(service.Source)
	service.TargetTls = clonePointer(service.TargetTls)
	if service.TargetTls != nil {
		service.TargetTls.Pem = clonePointer(service.TargetTls.Pem)
	}
	service.Placement = clonePointer(service.Placement)
	if service.Placement != nil {
		service.Placement.DomainId = clonePointer(service.Placement.DomainId)
		service.Placement.Hostname = clonePointer(service.Placement.Hostname)
		service.Placement.WorktreeKey = clonePointer(service.Placement.WorktreeKey)
		service.Placement.WorktreeLabel = clonePointer(service.Placement.WorktreeLabel)
	}
	service.HttpLimits = clonePointer(service.HttpLimits)
	if service.HttpLimits != nil {
		service.HttpLimits.Total = clonePointer(service.HttpLimits.Total)
		service.HttpLimits.Concurrency = clonePointer(service.HttpLimits.Concurrency)
		service.HttpLimits.Rate = clonePointer(service.HttpLimits.Rate)
		if service.HttpLimits.Rate != nil {
			service.HttpLimits.Rate.Burst = clonePointer(service.HttpLimits.Rate.Burst)
		}
	}
	return service
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	return new(*value)
}
