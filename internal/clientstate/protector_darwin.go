package clientstate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keychainService = "dev.tnl.client-state.v3"

func defaultProtection() ProtectionMode { return ProtectionKeychain }

// the caller holds the database initialization lock, including key creation.
func platformWrappingKey(ctx context.Context, account string, create bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, err := keyring.Get(keychainService, account)
	if errors.Is(err, keyring.ErrNotFound) && create {
		key := make([]byte, wrappingKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		value = base64.RawStdEncoding.EncodeToString(key)
		if err := keyring.Set(keychainService, account, value); err != nil {
			return nil, fmt.Errorf("clientstate: save Keychain wrapping key: %w", err)
		}
		value, err = keyring.Get(keychainService, account)
	}
	if err != nil {
		return nil, fmt.Errorf("clientstate: read Keychain wrapping key: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid Keychain wrapping key")
	}
	return key, nil
}
