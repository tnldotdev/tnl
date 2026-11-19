package state

import "reflect"

// only an explicit service binding can enable public endpoint access.
func projectServicePublic(service ProjectServiceConfiguration) bool {
	return service.Public != nil && *service.Public
}

// endpoint settings remain with control's validated endpoint owner, not a
// publisher's serving definition. desired reconciliation retains the full value.
func appliedPublicationConfiguration(service ProjectServiceConfiguration) ProjectServiceConfiguration {
	service.Public = nil
	service.Hostname = ""
	service.DomainID = ""
	service.CertificateScope = ""
	return service
}

// only changes to the serving definition replace existing publication authority.
func sameAppliedPublication(previous, current ProjectServiceConfiguration) bool {
	// changing the wildcard grant fences old publisher runs; endpoint-only
	// edits leave the run's captured grant and certificate authority unchanged.
	return previous.CertificateScope == current.CertificateScope &&
		reflect.DeepEqual(appliedPublicationConfiguration(previous), appliedPublicationConfiguration(current))
}
