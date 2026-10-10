package main

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
)

// commandDiagnostic is shared by finite command failures and publish events.
// only authored messages and actions cross the output boundary.
type commandDiagnostic struct {
	Reason    string     `json:"reason"`
	Code      string     `json:"code,omitempty"`
	Message   string     `json:"message"`
	HelpURL   string     `json:"help_url,omitempty"`
	Retryable bool       `json:"retryable"`
	RetryAt   *time.Time `json:"retry_at,omitempty"`
	Action    string     `json:"action,omitempty"`
	Command   []string   `json:"command,omitempty"`
}

func commandDiagnosticFor(err error) commandDiagnostic {
	err = classifyCommandError(err)
	presented := presentFailure(err)
	result := commandDiagnostic{Reason: string(presented.reason), Message: presented.message, Action: presented.action}
	if reason, definition, ok := failure.Describe(err); ok && string(reason) == result.Reason {
		result.Retryable = definition.Retry == failure.RetryLater
	} else {
		result.Retryable = errors.Is(err, controlclient.ErrUnavailable) || errors.Is(err, controlclient.ErrRateLimited) ||
			errors.Is(err, authorityclient.ErrUnavailable) || errors.Is(err, authorityclient.ErrRateLimited)
	}
	if code, ok := diagnostic.CodeOf(err); ok {
		result.Code, result.HelpURL = string(code), diagnostic.HelpURLForError(err)
	} else if url := failure.HelpURL(presented.reason, failure.KnownCase(err)); url != "" {
		result.Code, result.HelpURL = result.Reason, url
	}
	if result.Reason == string(failure.Authentication) || result.Code == string(diagnostic.AuthenticationRequired) {
		result.Action = "run tnl auth login explicitly, then retry this command"
		result.Command = []string{"tnl", "auth", "login", "start", "--output", "json"}
	}
	var limited *controlclient.RateLimitError
	var authorityLimited *authorityclient.RateLimitError
	delay := time.Duration(0)
	if errors.As(err, &limited) {
		delay = limited.RetryAfter
	} else if errors.As(err, &authorityLimited) {
		delay = authorityLimited.RetryAfter
	}
	if delay > 0 {
		at := time.Now().Add(delay).UTC()
		result.RetryAt = &at
	}
	return result
}

type machineCommandError struct{ error }

func (e *machineCommandError) Unwrap() error { return e.error }

// machineOutputRequested recognizes output intent before parsing. passthrough
// arguments belong to the child process and cannot choose the CLI error format.
func machineOutputRequested(args []string) bool {
	for index, argument := range args {
		if argument == "--" {
			break
		}
		if argument == "--output=json" || argument == "--output=ndjson" {
			return true
		}
		if argument == "--output" && index+1 < len(args) && (args[index+1] == "json" || args[index+1] == "ndjson") {
			return true
		}
	}
	return false
}

func writeMachineCommandError(output io.Writer, err error) {
	_ = json.NewEncoder(output).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Type          string `json:"type"`
		commandDiagnostic
	}{SchemaVersion: 1, Type: "error", commandDiagnostic: commandDiagnosticFor(err)})
}
