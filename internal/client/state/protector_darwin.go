package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const keychainService = "dev.tnl.client-state.v1"

func defaultProtection() ProtectionMode { return ProtectionKeychain }

// the caller holds the database initialization lock, including key creation.
func platformWrappingKey(ctx context.Context, account string, create bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	get, set := keyring.Get, keyring.Set
	if path, selected := os.LookupEnv("TNL_STATE_KEYCHAIN"); selected {
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
		get = func(service, account string) (string, error) {
			return namedKeychainGet(ctx, path, service, account)
		}
		set = func(service, account, value string) error {
			return namedKeychainSet(ctx, path, service, account, value)
		}
	}
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
		return nil, fmt.Errorf("clientstate: read Keychain wrapping key: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(key) != wrappingKeySize {
		return nil, errors.New("clientstate: invalid Keychain wrapping key")
	}
	return key, nil
}

func namedKeychainGet(ctx context.Context, path, service, account string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w", path)
	command.WaitDelay = time.Second
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var exit *exec.ExitError
		// errSecItemNotFound (-25300), represented by the command's exit byte.
		if errors.As(err, &exit) && exit.ExitCode() == 44 {
			return "", keyring.ErrNotFound
		}
		return "", err
	}
	value := strings.TrimSpace(string(output))
	// use the same stored value as the default go-keyring adapter.
	if encoded, ok := strings.CutPrefix(value, "go-keyring-base64:"); ok {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		return string(decoded), err
	}
	return value, nil
}

func namedKeychainSet(ctx context.Context, path, service, account, value string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	value = "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte(value))
	arguments := []string{"add-generic-password", "-s", service, "-a", account, "-w", value, "-T", "/usr/bin/security", path}
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
	command := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	command.Stdin = strings.NewReader(line)
	command.WaitDelay = time.Second
	err := command.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
