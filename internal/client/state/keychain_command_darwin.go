package state

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/zalando/go-keyring"
)

type keychainRunner func(context.Context, []string, string) ([]byte, error)

// security returns only the low byte of the signed OSStatus.
const (
	securityExitItemNotFound          = -25300 & 0xff // errSecItemNotFound
	securityExitInteractionRequired   = -25315 & 0xff // errSecInteractionRequired
	securityExitInteractionNotAllowed = -25308 & 0xff // errSecInteractionNotAllowed
	securityExitAuthFailed            = -25293 & 0xff // errSecAuthFailed
	securityExitUserCanceled          = -128 & 0xff   // errSecUserCanceled
)

func runKeychainCommand(ctx context.Context, arguments []string, input string) ([]byte, error) {
	return executeKeychainCommand(ctx, arguments, input, exec.CommandContext, 10*time.Second)
}

func executeKeychainCommand(ctx context.Context, arguments []string, input string, commandContext func(context.Context, string, ...string) *exec.Cmd, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := commandContext(ctx, "/usr/bin/security", arguments...)
	command.Stdin = strings.NewReader(input)
	command.WaitDelay = time.Second
	// security -i can echo the entire failed command, including its secret.
	// discard stderr and all write output, including in the retained cause.
	command.Stderr = io.Discard
	var output bytes.Buffer
	if input == "" {
		command.Stdout = &output
	} else {
		command.Stdout = io.Discard
	}
	err := command.Run() // CommandContext kills on cancellation; Run joins.
	if ctx.Err() != nil {
		kind := failure.KeychainTimeout
		if errors.Is(ctx.Err(), context.Canceled) {
			kind = failure.KeychainCanceled
		}
		return nil, &failure.ClientKeychainError{Kind: kind, Cause: errors.Join(ctx.Err(), err)}
	}
	if err == nil {
		return output.Bytes(), nil
	}
	var exit *exec.ExitError
	kind := failure.KeychainUnavailable
	if errors.As(err, &exit) {
		// security exposes only the low byte of OSStatus. these statuses do
		// not distinguish a locked keychain from missing interactive approval.
		switch exit.ExitCode() {
		case securityExitItemNotFound:
			// a write failure must never authorize another key creation.
			if input == "" {
				return nil, keyring.ErrNotFound
			}
		case securityExitInteractionRequired, securityExitInteractionNotAllowed, securityExitAuthFailed, securityExitUserCanceled:
			kind = failure.KeychainAccess
		}
	}
	return nil, &failure.ClientKeychainError{Kind: kind, Cause: err}
}
