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

// Setting is a code-owned configuration field name. its value is never stored
// with an error or printed by an output adapter.
type Setting string

const (
	SettingDatabaseURL          Setting = "TNLD_DATABASE_URL"
	SettingDatabaseDirectURL    Setting = "TNLD_DATABASE_DIRECT_URL"
	SettingStorageKey           Setting = "TNLD_STORAGE_KEY"
	SettingLoginToken           Setting = "TNLD_LOGIN_TOKEN"
	SettingMetricsListen        Setting = "TNLD_METRICS_LISTEN"
	SettingControlListen        Setting = "TNLD_CONTROL_LISTEN"
	SettingPrivateControlListen Setting = "TNLD_PRIVATE_CONTROL_LISTEN"
	SettingIngressListen        Setting = "TNLD_INGRESS_LISTEN"
	SettingRelayTCPListen       Setting = "TNLD_RELAY_TCP_LISTEN"
	SettingRelayUDPListen       Setting = "TNLD_RELAY_UDP_LISTEN"
	SettingInternalRelayListen  Setting = "TNLD_INTERNAL_RELAY_LISTEN"
	SettingDNSServer            Setting = "TNLD_DNS_SERVER"
	SettingEmailURL             Setting = "TNLD_EMAIL_URL"
	SettingWebhookSecret        Setting = "TNLD_WEBHOOK_SECRET"
	SettingWebServiceSecret     Setting = "TNLD_WEB_SERVICE_SECRET"
	SettingOIDCIssuer           Setting = "TNLD_OIDC_ISSUER"
)

func (setting Setting) valid() bool {
	switch setting {
	case SettingDatabaseURL, SettingDatabaseDirectURL, SettingStorageKey, SettingLoginToken,
		SettingMetricsListen, SettingControlListen, SettingPrivateControlListen, SettingIngressListen,
		SettingRelayTCPListen, SettingRelayUDPListen, SettingInternalRelayListen, SettingDNSServer,
		SettingEmailURL, SettingWebhookSecret, SettingWebServiceSecret, SettingOIDCIssuer:
		return true
	}
	return false
}

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
	setting   Setting
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

// WrapSetting adds a safe setting name, without storing or displaying the
// configured value. it is intended for validation errors with an exact field.
func WrapSetting(operation Operation, reason Reason, setting Setting, cause error) error {
	if cause == nil {
		return nil
	}
	if !setting.valid() {
		panic("failure: setting is not defined: " + string(setting))
	}
	err := Wrap(operation, reason, cause).(*Error)
	err.setting = setting
	return err
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.operation, e.cause) }
func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Operation() Operation { return e.operation }
func (e *Error) Reason() Reason       { return e.reason }
func (e *Error) Setting() Setting     { return e.setting }

// Of returns the outermost typed failure within an error chain.
func Of(err error) (*Error, bool) {
	var typed *Error
	return typed, errors.As(err, &typed)
}

// Describe returns authored text for the outermost typed failure.
func Describe(err error) (Reason, Definition, bool) {
	reason, ok := ReasonOf(err)
	if !ok {
		return "", Definition{}, false
	}
	definition, found := DefinitionFor(reason)
	return reason, definition, found
}

// ReasonOf also accepts domain errors that carry a typed reason while retaining
// their own error identities and retry behavior.
func ReasonOf(err error) (Reason, bool) {
	if typed, ok := Of(err); ok {
		return typed.reason, true
	}
	var reasoned interface{ FailureReason() Reason }
	if errors.As(err, &reasoned) {
		reason := reasoned.FailureReason()
		_, ok := DefinitionFor(reason)
		return reason, ok
	}
	return "", false
}
