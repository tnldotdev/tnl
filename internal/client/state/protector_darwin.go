package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/zalando/go-keyring"
)

const keychainService = "dev.tnl.client-state.v1"

func defaultProtection() ProtectionMode { return ProtectionKeychain }

// the caller holds the database initialization lock, including key creation.
func platformWrappingKey(ctx context.Context, account string, create bool) (key []byte, retErr error) {
	defer func() {
		if retErr != nil {
			if _, typed := errors.AsType[*failure.ClientKeychainError](retErr); !typed {
				kind := failure.KeychainUnavailable
				if errors.Is(retErr, context.Canceled) {
					kind = failure.KeychainCanceled
				} else if errors.Is(retErr, context.DeadlineExceeded) {
					kind = failure.KeychainTimeout
				}
				retErr = &failure.ClientKeychainError{Kind: kind, Cause: retErr}
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := ""
	if selectedPath, selected := os.LookupEnv("TNL_STATE_KEYCHAIN"); selected {
		path = selectedPath
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return nil, errors.New("clientstate: TNL_STATE_KEYCHAIN requires an absolute Keychain path")
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("clientstate: open selected Keychain: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("clientstate: selected Keychain must be a regular file")
		}
		// explicitly selected keychains never consult the default search list,
		// including when the selected file or its wrapping key is unavailable.
	}
	return wrappingKey(ctx, path, account, create)
}

func wrappingKey(ctx context.Context, path, account string, create bool) ([]byte, error) {
	get := func(service, account string) (string, error) {
		return namedKeychainGet(ctx, path, service, account)
	}
	set := func(service, account, value string) error {
		return namedKeychainSet(ctx, path, service, account, value)
	}
	if path == "" {
		if mock := memoryKeychain.Load(); mock != nil {
			get, set = mock.get, mock.set
		}
	}
	return loadKeychainWrappingKey(account, create, get, set)
}

func loadKeychainWrappingKey(account string, create bool, get func(string, string) (string, error), set func(string, string, string) error) ([]byte, error) {
	value, err := get(keychainService, account)
	if errors.Is(err, keyring.ErrNotFound) && create {
		key := make([]byte, wrappingKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		value = base64.RawStdEncoding.EncodeToString(key)
		if err := set(keychainService, account, value); err != nil {
			return nil, fmt.Errorf("clientstate: save Keychain wrapping key: %w", err)
		}
		value, err = get(keychainService, account)
	}
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			err = &failure.ClientKeychainError{Kind: failure.KeychainMissing, Cause: err}
		}
		return nil, fmt.Errorf("clientstate: read Keychain wrapping key: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid Keychain wrapping key")
	}
	return key, nil
}

func namedKeychainGet(ctx context.Context, path, service, account string) (string, error) {
	return keychainGet(ctx, path, service, account, runKeychainCommand)
}

func keychainGet(ctx context.Context, path, service, account string, run keychainRunner) (string, error) {
	arguments := []string{"find-generic-password", "-s", service, "-a", account, "-w"}
	if path != "" {
		arguments = append(arguments, path)
	}
	output, err := run(ctx, arguments, "")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	// use the same stored value as the default go-keyring adapter.
	if encoded, ok := strings.CutPrefix(value, "go-keyring-base64:"); ok {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", errors.New("clientstate: invalid Keychain value encoding")
		}
		return string(decoded), nil
	}
	if encoded, ok := strings.CutPrefix(value, "go-keyring-encoded:"); ok {
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			return "", errors.New("clientstate: invalid Keychain value encoding")
		}
		return string(decoded), nil
	}
	return value, nil
}

func namedKeychainSet(ctx context.Context, path, service, account, value string) error {
	return keychainSet(ctx, path, service, account, value, runKeychainCommand)
}

func keychainSet(ctx context.Context, path, service, account, value string, run keychainRunner) error {
	value = "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte(value))
	// preserve the default adapter's item ACL; explicitly selected keychains
	// retain their existing security-only ACL and never use the search list.
	arguments := []string{"add-generic-password", "-s", service, "-a", account, "-w", value}
	if path != "" {
		arguments = append(arguments, "-T", "/usr/bin/security", path)
	}
	for i, argument := range arguments {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("clientstate: invalid Keychain command argument")
		}
		// security's stdin parser accepts quoted arguments with backslash escapes;
		// it does not implement shell concatenation or shell expansion.
		arguments[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(argument) + `"`
	}
	line := strings.Join(arguments, " ") + "\n"
	if len(line) >= 4096 {
		return errors.New("clientstate: selected Keychain path is too long")
	}
	// keep the wrapping key out of the process argument list and diagnostics.
	_, err := run(ctx, []string{"-i"}, line)
	return err
}
