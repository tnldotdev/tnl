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

// LocalProjectIdentity keeps the checkout mapping on this machine.
// concurrent callers share the first committed random identifiers, not path hashes.
func (d *Database) LocalProjectIdentity(ctx context.Context, root, checkoutKey string) (string, string, error) {
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
	key := canonical
	queries := d.queries
	var commit func() error
	if checkoutKey != "" {
		key = "checkout:" + checkoutKey
		// consume the directory-only receipt on its first git binding. a
		// later checkout at this path cannot inherit the bound checkout's IDs.
		tx, err := d.db.BeginTx(ctx, nil)
		if err != nil {
			return "", "", err
		}
		defer tx.Rollback()
		queries = queries.WithTx(tx)
		if err := queries.BindDirectoryIdentityToCheckout(ctx, clientstatedb.BindDirectoryIdentityToCheckoutParams{
			CheckoutKey: key, Directory: canonical,
		}); err != nil {
			return "", "", err
		}
		commit = tx.Commit
	}
	var entropy [64]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", "", err
	}
	row, err := queries.EnsureLocalProjectIdentity(ctx, clientstatedb.EnsureLocalProjectIdentityParams{
		ProjectRoot: key, SourceID: hex.EncodeToString(entropy[:32]), WorktreeID: hex.EncodeToString(entropy[32:]),
	})
	if err != nil {
		return "", "", err
	}
	if commit != nil {
		if err := commit(); err != nil {
			return "", "", err
		}
	}
	return row.SourceID, row.WorktreeID, nil
}
