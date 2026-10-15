package clientstate

import (
	"context"
	"path/filepath"
)

type secretProtector interface {
	Seal(context.Context, string, []byte) ([]byte, error)
	Open(context.Context, string, []byte) ([]byte, error)
}

// WrappingKeyPath keeps file-protected v1 state separate from older client
// databases and their wrapping keys.
func WrappingKeyPath(root string) string { return filepath.Join(root, "v1.wrapping-key") }
