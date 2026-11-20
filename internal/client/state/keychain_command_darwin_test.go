package state

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/zalando/go-keyring"
)

func TestKeychainDefaultAndSelectedCommandsStopAndJoin(t *testing.T) {
	for _, path := range []string{"", "/selected.keychain"} {
		for _, write := range []bool{false, true} {
			for _, cancelCaller := range []bool{false, true} {
				t.Run(fmt.Sprintf("path=%s/write=%v/cancel=%v", path, write, cancelCaller), func(t *testing.T) {
					ready, signal, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					defer ready.Close()
					defer signal.Close()
					if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					var child *exec.Cmd
					factory := func(ctx context.Context, executable string, args ...string) *exec.Cmd {
						if executable != "/usr/bin/security" || slices.Contains(args, "private wrapping key") {
							t.Error("unsafe Keychain command", executable, args)
						}
						child = exec.CommandContext(ctx, "/bin/sh", "-c", "printf r >&3; exec /bin/sleep 60")
						child.ExtraFiles = []*os.File{signal}
						return child
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					done := make(chan error, 1)
					timeout := time.Second
					if cancelCaller {
						timeout = time.Minute
					}
					run := func(ctx context.Context, args []string, input string) ([]byte, error) {
						if write {
							if !slices.Equal(args, []string{"-i"}) || !strings.Contains(input, "go-keyring-base64:") {
								t.Error("write did not use private stdin")
							}
						} else if (path != "" && args[len(args)-1] != path) || (path == "" && slices.Contains(args, "")) {
							t.Error("Keychain selection changed", args)
						}
						return executeKeychainCommand(ctx, args, input, factory, timeout)
					}
					go func() {
						var err error
						if write {
							err = keychainSet(ctx, path, keychainService, "account", "private wrapping key", run)
						} else {
							_, err = keychainGet(ctx, path, keychainService, "account", run)
						}
						done <- err
					}()
					if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
						cancel()
						<-done
						t.Fatal("child readiness", err)
					}
					if cancelCaller {
						cancel()
					}
					err = <-done
					want, kind := context.DeadlineExceeded, failure.KeychainTimeout
					if cancelCaller {
						want, kind = context.Canceled, failure.KeychainCanceled
					}
					typed, ok := errors.AsType[*failure.ClientKeychainError](err)
					if !errors.Is(err, want) || !ok || typed.Kind != kind {
						t.Fatalf("cancellation classification = %v", err)
					}
					if child.ProcessState == nil {
						t.Fatal("returned without joining child")
					}
					if errors.Is(err, keyring.ErrNotFound) {
						t.Fatal("canceled operation became not-found")
					}
				})
			}
		}
	}
}

func TestKeychainCommandClassifiesStatusWithoutRetainingOutput(t *testing.T) {
	for _, test := range []struct {
		status int
		kind   failure.KeychainFailure
	}{
		{21, failure.KeychainAccess}, {36, failure.KeychainAccess},
		{51, failure.KeychainAccess}, {128, failure.KeychainAccess},
		{53, failure.KeychainUnavailable}, {1, failure.KeychainUnavailable},
		{44, failure.KeychainMissing},
	} {
		for _, write := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/write=%v", test.status, write), func(t *testing.T) {
				input := ""
				if write {
					input = "secret stdin"
				}
				factory := func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
					return exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("printf 'secret stdout'; printf 'secret stderr' >&2; exit %d", test.status))
				}
				output, err := executeKeychainCommand(t.Context(), []string{"-i"}, input, factory, time.Second)
				if test.status == 44 && !write {
					if !errors.Is(err, keyring.ErrNotFound) {
						t.Fatal("genuine missing item not recognized", err)
					}
				} else {
					kind := test.kind
					if test.status == 44 {
						kind = failure.KeychainUnavailable
					}
					typed, ok := errors.AsType[*failure.ClientKeychainError](err)
					if !ok || typed.Kind != kind || errors.Is(err, keyring.ErrNotFound) {
						t.Fatalf("incorrect Keychain status classification: %#v", err)
					}
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != test.status || len(exit.Stderr) != 0 {
						t.Fatal("lost status or retained stderr", err)
					}
				}
				for cause := err; cause != nil; cause = errors.Unwrap(cause) {
					if strings.Contains(cause.Error(), "secret") && cause != keyring.ErrNotFound {
						t.Fatal("retained command output")
					}
				}
				if len(output) != 0 {
					t.Fatal("failed command returned secret output")
				}
			})
		}
	}
}

func TestKeychainCommandUnavailableAndAlreadyCanceled(t *testing.T) {
	factory := func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/tnl-security")
	}
	_, err := executeKeychainCommand(t.Context(), nil, "", factory, time.Second)
	typed, ok := errors.AsType[*failure.ClientKeychainError](err)
	if !ok || typed.Kind != failure.KeychainUnavailable || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing executable classification", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = executeKeychainCommand(ctx, nil, "", factory, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation ignored", err)
	}
}

func TestKeychainStoredValueCompatibility(t *testing.T) {
	value := base64.RawStdEncoding.EncodeToString(make([]byte, wrappingKeySize))
	for _, encoded := range []string{
		value, "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte(value)),
		"go-keyring-encoded:" + hex.EncodeToString([]byte(value)),
	} {
		for _, path := range []string{"", "/selected.keychain"} {
			got, err := keychainGet(t.Context(), path, keychainService, "account", func(context.Context, []string, string) ([]byte, error) {
				return []byte(encoded + "\n"), nil
			})
			if err != nil || got != value {
				t.Fatal("released stored value not decoded", err)
			}
		}
	}
}

func TestKeychainFailuresNeverCreateOrReplaceWrappingKey(t *testing.T) {
	for _, kind := range []failure.KeychainFailure{failure.KeychainAccess, failure.KeychainTimeout, failure.KeychainCanceled, failure.KeychainUnavailable} {
		for _, create := range []bool{false, true} {
			cause := &failure.ClientKeychainError{Kind: kind, Cause: context.DeadlineExceeded}
			sets := 0
			_, err := loadKeychainWrappingKey("account", create,
				func(string, string) (string, error) { return "", cause },
				func(string, string, string) error { sets++; return nil })
			if !errors.Is(err, cause) || sets != 0 {
				t.Fatal("failed read created or replaced a wrapping key", err, sets)
			}
		}
	}
	sets := 0
	_, err := loadKeychainWrappingKey("account", true,
		func(string, string) (string, error) { return "", keyring.ErrNotFound },
		func(string, string, string) error {
			sets++
			return &failure.ClientKeychainError{Kind: failure.KeychainAccess}
		})
	if sets != 1 || failure.KnownCase(failure.Wrap("open client state", failure.ClientStateUnavailable, err)) != "keychain-access" {
		t.Fatal("write denial was not preserved", err, sets)
	}
}
