package main

import (
	"errors"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
)

type presentedFailure struct {
	reason  failure.Reason
	message string
	action  string
}

// presentHumanFailure adds bounded policy guidance without changing machine output.
func presentHumanFailure(err error) presentedFailure {
	if failure.Only(err, authorization.ErrIPPrefixLimit) {
		return presentedFailure{reason: failure.InvalidCommand, message: authorization.ErrIPPrefixLimit.Error(),
			action: "remove prefixes and retry; equivalent addresses count once"}
	}
	var namespace *clientcontrol.ServiceNamespaceError
	if errors.As(err, &namespace) && namespace != nil {
		if allowed, ok := namespace.AllowedNamespace(); ok && failure.Only(err, namespace) {
			return presentedFailure{reason: failure.ServerResourceNotFound, message: "service hostname is not permitted",
				action: "use a hostname below " + allowed}
		}
		// a matching denial must not hide an independent operation or cleanup fault.
		definition, _ := failure.DefinitionFor(failure.Unexpected)
		return presentedFailure{reason: failure.Unexpected, message: definition.Message, action: definition.Action}
	}
	return presentFailure(err)
}

// presentFailure uses authored messages and explicitly approved fields.
func presentFailure(err error) presentedFailure {
	var problem *clientcontrol.ProblemError
	if errors.As(err, &problem) {
		if id, ok := problem.CredentialDeliveryResourceID(); ok {
			return presentedFailure{reason: failure.ServerConflict, message: "credential delivery unavailable", action: "revoke " + id + ", then create with a new key"}
		}
	}
	if code, ok := diagnostic.CodeOf(err); ok {
		return presentedFailure{reason: failure.Reason(code), message: diagnostic.Summary(code)}
	}
	if reason, definition, ok := failure.Describe(err); ok {
		return presentedFailure{reason: reason, message: definition.Message, action: definition.Action}
	}
	definition, _ := failure.DefinitionFor(failure.Unexpected)
	return presentedFailure{reason: failure.Unexpected, message: definition.Message, action: definition.Action}
}
