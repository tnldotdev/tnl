//go:build !darwin

package clientstate

import (
	"context"
	"errors"
)

func defaultProtection() ProtectionMode { return ProtectionFile }

func platformWrappingKey(context.Context, string, bool) ([]byte, error) {
	return nil, errors.New("clientstate: Keychain protection requires macOS")
}
