package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
)

type presentedFailure struct {
	reason  failure.Reason
	message string
	action  string
}

type commandFollowup struct {
	error
	block clioutput.Block
}

func (e *commandFollowup) Unwrap() error { return e.error }

func withCommandFollowup(err error, diagnostics io.Writer, label, command string) error {
	block := clioutput.Section(label, clioutput.Literal(command))
	if err == nil || failure.Only(err, context.Canceled) {
		// a clean stop has no terminal error to carry the command.
		return errors.Join(err, writeResult(diagnostics, block))
	}
	return &commandFollowup{err, block}
}

// use pflag's structured names, never its error text or the supplied value.
func flagErrorMessage(err error) string {
	if unknown, ok := errors.AsType[*pflag.NotExistError](err); ok && unknown != nil && failure.Only(err, unknown) {
		name := unknown.GetSpecifiedName()
		const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		if len(name) == 0 || len(name) > 64 || strings.Trim(name, letters+"-") != "" {
			return "Unknown flag."
		}
		if unknown.GetSpecifiedShortnames() != "" {
			return "Unknown flag: -" + name
		}
		return "Unknown flag: --" + name
	}
	if missing, ok := errors.AsType[*pflag.ValueRequiredError](err); ok && missing != nil && failure.Only(err, missing) {
		return "Missing value for --" + missing.GetFlag().Name
	}
	if invalid, ok := errors.AsType[*pflag.InvalidValueError](err); ok && invalid != nil && failure.Only(err, invalid) {
		return "Invalid value for --" + invalid.GetFlag().Name
	}
	if syntax, ok := errors.AsType[*pflag.InvalidSyntaxError](err); ok && syntax != nil && failure.Only(err, syntax) {
		return "Invalid flag syntax."
	}
	return ""
}

type missingServiceName struct{ name string }

func (*missingServiceName) Error() string { return "service is not configured" }

func unconfiguredService(name string) error {
	return failure.Wrap("wait for service", failure.ServiceNotConfigured, &missingServiceName{name: name})
}

// presentHumanFailure adds bounded policy guidance without changing machine output.
func presentHumanFailure(err error) presentedFailure {
	if message := flagErrorMessage(err); message != "" {
		command, ok := clioutput.CommandOf(err)
		if !ok {
			command = "tnl"
		}
		presented := presentFailure(err)
		presented.message, presented.action = message, command+" --help"
		return presented
	}
	if probe, ok := errors.AsType[*pingFailure](err); ok && probe != nil && failure.Only(err, probe) {
		reason, _ := failure.ReasonOf(err)
		return presentedFailure{reason: reason, message: probe.message()}
	}
	if service, ok := errors.AsType[*missingServiceName](err); ok && service != nil && failure.Only(err, service) && naming.ValidServiceName(service.name) {
		return presentedFailure{reason: failure.ServiceNotConfigured,
			message: fmt.Sprintf("Service %q is not configured.", service.name), action: "Check the service name in your project configuration."}
	}
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
