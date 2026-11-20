package failure

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestKeychainCasesPreserveDiagnosticIdentityAndCause(t *testing.T) {
	for _, test := range []struct {
		kind KeychainFailure
		id   string
	}{
		{KeychainAccess, "keychain-access"}, {KeychainTimeout, "keychain-timeout"},
		{KeychainCanceled, "keychain-canceled"}, {KeychainUnavailable, "keychain-unavailable"},
		{KeychainMissing, "keychain-missing"},
	} {
		err := Wrap("open client state", ClientStateUnavailable, &ClientKeychainError{Kind: test.kind, Cause: context.DeadlineExceeded})
		if KnownCase(err) != test.id || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("classification or cause lost: %s, %v", KnownCase(err), err)
		}
		reason, definition, ok := Describe(err)
		if !ok || reason != ClientStateUnavailable || definition.Retry != RetryAfterChange ||
			HelpURL(reason, KnownCase(err)) != "https://tnl.dev/c/state-unavailable?case="+test.id {
			t.Fatal("public diagnostic identity changed", err)
		}
	}
	permission := Wrap("open client state", ClientStateUnavailable, fs.ErrPermission)
	if KnownCase(permission) != "permission-denied" {
		t.Fatal("existing file permission case changed")
	}
	spoof := Wrap("open client state", ClientStateUnavailable, errors.New("User interaction is not allowed. (-25308) keychain-access"))
	if KnownCase(spoof) != "" || strings.Contains(SafeMessage(spoof, Unexpected), "-25308") {
		t.Fatal("cause text classified or exposed")
	}
}
