package state

import "reflect"

// explicit binding reachability overrides the retained deployment default.
// the latter preserves configurations saved before per-service exposure.
func projectServicePublic(settings *DeploymentSettings, service ProjectServiceConfiguration) bool {
	if service.Public != nil {
		return *service.Public
	}
	return settings != nil && settings.Public
}

// publication mechanics and endpoint reachability have separate lifetimes.
// the endpoint owner fences the first allocated port; retained exposure changes
// cannot revoke a publisher grant or close an authorized private run.
func sameAppliedPublication(previous, current ProjectServiceConfiguration) bool {
	previous.Public, current.Public = nil, nil
	return reflect.DeepEqual(previous, current)
}
