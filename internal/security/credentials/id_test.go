package credentials

import (
	"errors"
	"testing"
)

func TestParseCredentialID(t *testing.T) {
	_, credentialID, _, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCredentialID(credentialID.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != credentialID {
		t.Fatalf("credential ID = %q, want %q", parsed, credentialID)
	}

	for name, value := range map[string]string{
		"empty":            "",
		"too short":        credentialID.String()[:len(credentialID)-1],
		"too long":         credentialID.String() + "A",
		"padded":           credentialID.String() + "==",
		"non-URL alphabet": "++++++++++++++++++++++",
	} {
		t.Run(name, func(t *testing.T) {
			if parsed, err := ParseCredentialID(value); !errors.Is(err, ErrInvalidCredentialID) || parsed != "" {
				t.Fatalf("ParseCredentialID(%q) = %q, %v", value, parsed, err)
			}
		})
	}
}
