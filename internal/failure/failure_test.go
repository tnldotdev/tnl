package failure

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestFailureKeepsCauseOutOfPublicDescription(t *testing.T) {
	cause := errors.New("postgresql://user:secret@database.example/tnl")
	err := Wrap("connect to control database", DatabaseUnavailable, cause)
	if !errors.Is(err, cause) {
		t.Fatal("typed failure did not preserve its cause")
	}
	reason, definition, ok := Describe(fmt.Errorf("outer: %w", err))
	if !ok || reason != DatabaseUnavailable || definition.Class != Unavailable || definition.Retry != RetryLater {
		t.Fatalf("typed failure = %q, %#v, %t", reason, definition, ok)
	}
	if strings.Contains(definition.Message+definition.Action, "secret") || !strings.Contains(err.Error(), "secret") {
		t.Fatal("public copy or internal cause changed")
	}
}

func TestClientCatalogAndSafeHelpContext(t *testing.T) {
	entries := ClientReasons()
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Message == "" || entry.Action == "" || seen[entry.Slug] ||
			!strings.HasPrefix(string(entry.Code), "TNL_CLIENT_") || HelpURL(entry.Code, "") != "https://tnl.dev/c/"+entry.Slug {
			t.Fatalf("invalid client entry: %+v", entry)
		}
		seen[entry.Slug] = true
	}
	if len(entries) < 50 {
		t.Fatalf("missing client failures: %d", len(entries))
	}
	err := Wrap("read client state", ClientStateUnavailable, fs.ErrPermission)
	if got := HelpURL(ClientStateUnavailable, KnownCase(err)); got != "https://tnl.dev/c/state-unavailable?case=permission-denied" {
		t.Fatalf("contextual link = %q", got)
	}
	if got := HelpURL(ClientStateUnavailable, "permission-denied&token=secret"); got != "https://tnl.dev/c/state-unavailable" {
		t.Fatalf("untrusted context = %q", got)
	}
	if got := HelpURL(DatabaseUnavailable, ""); got != "" {
		t.Fatalf("server failure has a client page: %q", got)
	}
}

func TestEveryReasonHasActionAndKnownClass(t *testing.T) {
	for _, reason := range Reasons() {
		definition, ok := DefinitionFor(reason)
		if !ok || definition.Message == "" || definition.Action == "" || definition.Class == "" ||
			definition.Retry > RetryAfterChange {
			t.Fatalf("incomplete definition for %q: %#v", reason, definition)
		}
	}
}

type domainFailure struct{ error }

func (domainFailure) FailureReason() Reason { return ServerDNSConflict }
func (e domainFailure) Unwrap() error       { return e.error }

func TestDomainFailureKeepsItsTypeAndSafeReason(t *testing.T) {
	cause := domainFailure{errors.New("provider returned token=secret")}
	err := fmt.Errorf("reconcile DNS: %w", cause)
	if !errors.Is(err, cause.error) {
		t.Fatal("domain failure lost its cause")
	}
	reason, definition, ok := Describe(err)
	if !ok || reason != ServerDNSConflict || strings.Contains(definition.Message+definition.Action, "secret") {
		t.Fatalf("domain failure = %q, %#v, %t", reason, definition, ok)
	}
}

func TestSettingContextNamesOnlyAnAllowedField(t *testing.T) {
	cause := errors.New("postgresql://user:secret@database.example/tnl")
	err := WrapSetting("validate database URL", ServerDatabaseURLInvalid, SettingDatabaseURL, cause)
	typed, ok := Of(fmt.Errorf("serve control: %w", err))
	if !ok || typed.Setting() != SettingDatabaseURL || !errors.Is(err, cause) {
		t.Fatalf("typed setting = %v, cause = %v", typed, err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown or user-supplied setting was accepted")
		}
	}()
	_ = WrapSetting("validate database URL", ServerDatabaseURLInvalid, Setting("postgresql://secret"), cause)
}

type failureAs struct{ value *Error }

func (failureAs) Error() string { return "custom failure" }
func (e failureAs) As(target any) bool {
	if out, ok := target.(**Error); ok {
		*out = e.value
		return true
	}
	return false
}

type reasonMarker struct{}

func (reasonMarker) FailureReason() Reason { return ServerDNSConflict }

type reasonAs struct{}

func (reasonAs) Error() string { return "custom reason" }
func (reasonAs) As(target any) bool {
	if out, ok := target.(*interface{ FailureReason() Reason }); ok {
		*out = reasonMarker{}
		return true
	}
	return false
}

func TestFailureExtractionContractsAndPrecedence(t *testing.T) {
	cause := errors.New("secret cause")
	first := newError("connect database", DatabaseUnavailable, cause)
	second := newError("validate database", ServerDatabaseURLInvalid, cause)
	for _, err := range []error{first, fmt.Errorf("outer: %w", first), errors.Join(first, second), failureAs{first}, errors.Join(domainFailure{cause}, first)} {
		typed, ok := Of(err)
		if !ok || typed != first {
			t.Fatalf("Of = %p, %t; want %p", typed, ok, first)
		}
		reason, definition, ok := Describe(err)
		if !ok || reason != DatabaseUnavailable || definition.Retry != RetryLater {
			t.Fatalf("typed failure lost retry precedence: %q, %+v, %t", reason, definition, ok)
		}
	}
	if reason, definition, ok := Describe(reasonAs{}); !ok || reason != ServerDNSConflict || definition.Retry != RetryAfterChange {
		t.Fatalf("custom marker As lost reason or retry: %q, %+v, %t", reason, definition, ok)
	}
	for _, err := range []error{nil, cause, (*Error)(nil), failureAs{}} {
		if typed, ok := Of(err); ok || typed != nil {
			t.Fatalf("Of accepted absent failure: %p, %t", typed, ok)
		}
		if _, _, ok := Describe(err); ok {
			t.Fatal("unclassified error acquired a definition")
		}
		if err != nil && SafeMessage(err, Unexpected) == "" {
			t.Fatal("non-nil error became successful output")
		}
	}
	if Wrap("", "", nil) != nil || WrapSetting("", "", "", nil) != nil {
		t.Fatal("nil causes must remain nil")
	}
	setting := WrapSetting("validate database", ServerDatabaseURLInvalid, SettingDatabaseURL, cause)
	typed, ok := Of(setting)
	if !errors.Is(setting, cause) || !ok || typed.Setting() != SettingDatabaseURL {
		t.Fatal("setting wrapper lost its cause or safe setting")
	}
}
