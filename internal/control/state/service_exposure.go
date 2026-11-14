package state

import "reflect"

// only an explicit service binding can enable public endpoint access.
func projectServicePublic(service ProjectServiceConfiguration) bool {
	return service.Public != nil && *service.Public
}

// publication mechanics and endpoint reachability have separate lifetimes.
// the endpoint owner fences the first allocated port; retained exposure changes
// cannot revoke a publisher grant or close an authorized private run.
func sameAppliedPublication(previous, current ProjectServiceConfiguration) bool {
	previous.Public, current.Public = nil, nil
	return reflect.DeepEqual(previous, current)
}
