package main

import (
	"errors"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

type presentedFailure struct {
	reason  failure.Reason
	message string
	action  string
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
