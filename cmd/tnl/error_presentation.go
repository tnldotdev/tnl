package main

import (
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
)

type presentedFailure struct {
	reason  failure.Reason
	message string
	action  string
}

// presentFailure chooses authored output without reading the internal cause.
func presentFailure(err error) presentedFailure {
	if code, ok := diagnostic.CodeOf(err); ok {
		return presentedFailure{reason: failure.Reason(code), message: diagnostic.Summary(code)}
	}
	if reason, definition, ok := failure.Describe(err); ok {
		return presentedFailure{reason: reason, message: definition.Message, action: definition.Action}
	}
	definition, _ := failure.DefinitionFor(failure.Unexpected)
	return presentedFailure{reason: failure.Unexpected, message: definition.Message, action: definition.Action}
}
