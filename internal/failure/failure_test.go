package failure

import (
	"errors"
	"fmt"
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
