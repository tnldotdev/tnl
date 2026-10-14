//go:build !darwin

package clientstate

import "context"

func newSecretProtector(account, _, root string) secretProtector {
	return newFileSecretProtector(account, root)
}

func prepareSecretProtection(ctx context.Context, root string, exists bool) error {
	return prepareFileSecretProtection(ctx, root, exists)
}
