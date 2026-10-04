package storagekey

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestKeyringRoundTripAndContextBinding(t *testing.T) {
	keyring, err := New(encodedKey(1), "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := keyring.Seal("table.column\x00row", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := keyring.Seal("table.column\x00row", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || bytes.Contains(first, []byte("secret")) {
		t.Fatal("ciphertexts must be randomized and must not contain plaintext")
	}
	plaintext, previous, err := keyring.Open(keyring.CurrentID(), "table.column\x00row", first)
	if err != nil || previous || string(plaintext) != "secret" {
		t.Fatalf("open = %q, %t, %v", plaintext, previous, err)
	}
	if _, _, err := keyring.Open(keyring.CurrentID(), "table.column\x00other", first); err == nil {
		t.Fatal("ciphertext was accepted in another context")
	}
	first[len(first)-1] ^= 1
	if _, _, err := keyring.Open(keyring.CurrentID(), "table.column\x00row", first); err == nil {
		t.Fatal("corrupt ciphertext was accepted")
	}
}

func TestKeyringOpensPreviousKey(t *testing.T) {
	oldKeyring, err := New(encodedKey(1), "")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := oldKeyring.Seal("context", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := New(encodedKey(2), encodedKey(1))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, previous, err := keyring.Open(keyring.PreviousID(), "context", ciphertext)
	if err != nil || !previous || string(plaintext) != "secret" {
		t.Fatalf("open previous = %q, %t, %v", plaintext, previous, err)
	}
	if keyring.CurrentID() == "" || keyring.PreviousID() == "" || keyring.CurrentID() == keyring.PreviousID() {
		t.Fatal("key IDs are invalid")
	}
	if _, _, err := keyring.Open("unknown", "context", ciphertext); err == nil {
		t.Fatal("unknown key ID was accepted")
	}
}

func TestKeyringRejectsInvalidConfiguration(t *testing.T) {
	for name, keys := range map[string][2]string{
		"missing current":   {"", ""},
		"short current":     {base64.RawURLEncoding.EncodeToString(make([]byte, 31)), ""},
		"padded current":    {base64.URLEncoding.EncodeToString(make([]byte, 32)), ""},
		"malformed current": {"not+a+key", ""},
		"invalid previous":  {encodedKey(1), "invalid"},
		"repeated key":      {encodedKey(1), encodedKey(1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(keys[0], keys[1]); err == nil {
				t.Fatal("invalid keyring was accepted")
			}
		})
	}
}

func TestIPPolicyKeysArePurposeBoundAcrossStorageKeyRotation(t *testing.T) {
	first, err := New(encodedKey(1), "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := first.IPPolicyKey(first.CurrentID(), "guest:one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.IPPolicyKey(first.CurrentID(), "issuance")
	if err != nil || before == second || before == [32]byte{} {
		t.Fatalf("purpose keys overlap: %x %x, %v", before, second, err)
	}
	rotated, err := New(encodedKey(2), encodedKey(1))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := rotated.IPPolicyKey(rotated.PreviousID(), "guest:one")
	if err != nil || previous != before {
		t.Fatalf("previous verifier changed: %x, %v", previous, err)
	}
	current, err := rotated.IPPolicyKey(rotated.CurrentID(), "guest:one")
	if err != nil || current == before {
		t.Fatalf("rotation retained the old verifier: %x, %v", current, err)
	}
	if _, err := rotated.IPPolicyKey("unavailable", "guest:one"); err == nil {
		t.Fatal("unknown key version accepted")
	}
}

func encodedKey(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, keySize))
}
