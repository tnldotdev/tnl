package failure

import (
	"errors"
	"strings"
	"testing"
)

func TestSafeMessageRetainsClassificationWithoutCauseText(t *testing.T) {
	cause := errors.New("private database credentials")
	err := Wrap("verify identity", ServerIdentityProviderUnavailable, cause)
	message := SafeMessage(err, Unexpected)
	if !errors.Is(err, cause) || !strings.Contains(message, "identity provider") || strings.Contains(message, cause.Error()) {
		t.Fatalf("unsafe or unclassified message = %q", message)
	}
	if SafeMessage(nil, Unexpected) != "" {
		t.Fatal("nil failure produced a message")
	}
	if message := SafeMessage(cause, Reason("not-defined")); !strings.Contains(message, "unexpectedly") || strings.Contains(message, cause.Error()) {
		t.Fatalf("unsafe fallback = %q", message)
	}
}
