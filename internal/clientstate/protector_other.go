//go:build !darwin

package clientstate

import (
	"context"
	"path/filepath"
)

func newSecretProtector(account, _, root string) secretProtector {
	return &fileSecretProtector{
		account: account, keyPath: filepath.Join(root, "wrapping-key-v1"),
	}
}

func prepareSecretProtection(ctx context.Context, root string, databaseExists bool) error {
	return prepareFileSecretProtection(ctx, root, databaseExists)
}
