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
