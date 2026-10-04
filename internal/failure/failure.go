// Package failure describes a failed operation without tying it to a CLI, log,
// HTTP, or tunnel representation.
package failure

import (
	"errors"
	"fmt"
)

// Reason identifies one actionable failure. ids remain stable when they are
// exposed to machine clients; a changed meaning needs a new reason.
type Reason string

// Operation names the work being attempted, not a package or error string.
type Operation string

// Class groups reasons for retry and transport decisions. a class is not a
// replacement for the more specific Reason.
type Class string

const (
	Invalid         Class = "invalid"
	Unauthenticated Class = "unauthenticated"
	Forbidden       Class = "forbidden"
	NotFound        Class = "not_found"
	Conflict        Class = "conflict"
	Stale           Class = "stale"
	Unavailable     Class = "unavailable"
	RateLimited     Class = "rate_limited"
	Degraded        Class = "degraded"
	Internal        Class = "internal"
)

// Retry describes whether retrying the same operation can make progress.
type Retry uint8

const (
	NoRetry Retry = iota
	RetryLater
	RetryAfterChange
)

// Definition is safe copy for one reason. causes and input values must not be
// interpolated into Message or Action.
type Definition struct {
	Class   Class
	Message string
	Action  string
	Retry   Retry
}

// Error keeps internal operation context and the original cause. presentation
// uses DefinitionFor instead of parsing Error().
type Error struct {
	operation Operation
	reason    Reason
	cause     error
}

// Wrap adds a reason to a non-nil cause. an invalid reason or operation is a
// programming error, so it fails at construction rather than at presentation.
func Wrap(operation Operation, reason Reason, cause error) error {
	if cause == nil {
		return nil
	}
	if operation == "" {
		panic("failure: operation is required")
	}
	if _, found := DefinitionFor(reason); !found {
		panic("failure: reason is not defined: " + string(reason))
	}
	return &Error{operation: operation, reason: reason, cause: cause}
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.operation, e.cause) }
func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Operation() Operation { return e.operation }
func (e *Error) Reason() Reason       { return e.reason }

// Of returns the outermost typed failure within an error chain.
func Of(err error) (*Error, bool) {
	var typed *Error
	return typed, errors.As(err, &typed)
}

// Describe returns authored text for the outermost typed failure.
func Describe(err error) (Reason, Definition, bool) {
	typed, ok := Of(err)
	if !ok {
		return "", Definition{}, false
	}
	definition, found := DefinitionFor(typed.reason)
	return typed.reason, definition, found
}
