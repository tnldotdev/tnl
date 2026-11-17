package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

// LocalProjectIdentity keeps the canonical directory mapping on this machine.
// concurrent callers share the first committed random identifiers, not path hashes.
func (d *Database) LocalProjectIdentity(ctx context.Context, root string) (string, string, error) {
	if !filepath.IsAbs(root) {
		return "", "", errors.New("local project identity needs a canonical directory")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() {
		return "", "", errors.New("local project identity needs a directory")
	}
	var entropy [64]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", "", err
	}
	row, err := d.queries.EnsureLocalProjectIdentity(ctx, clientstatedb.EnsureLocalProjectIdentityParams{
		ProjectRoot: canonical, SourceID: hex.EncodeToString(entropy[:32]), WorktreeID: hex.EncodeToString(entropy[32:]),
	})
	return row.SourceID, row.WorktreeID, err
}
