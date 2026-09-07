package clientstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const installationIDPrefix = "installation_"

const worktreeHashSaltLength = 32

// InstallationID returns the stable pseudonymous identifier for this client database.
func (d *Database) InstallationID(ctx context.Context) (string, error) {
	id, err := d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: read installation ID: %w", err)
	}
	if id != "" {
		if !validInstallationID(id) {
			return "", errors.New("clientstate: installation ID is invalid")
		}
		return id, nil
	}
	generated, err := opaqueid.New(installationIDPrefix)
	if err != nil {
		return "", fmt.Errorf("clientstate: generate installation ID: %w", err)
	}
	if err := d.queries.SetInstallationID(ctx, generated); err != nil {
		return "", fmt.Errorf("clientstate: save installation ID: %w", err)
	}
	id, err = d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: reread installation ID: %w", err)
	}
	if !validInstallationID(id) {
		return "", errors.New("clientstate: installation ID is invalid")
	}
	return id, nil
}

func validInstallationID(id string) bool {
	return opaqueid.Valid(id, installationIDPrefix)
}

// WorktreeHashSalt returns private key material shared by worktrees using this
// client database.
func (d *Database) WorktreeHashSalt(ctx context.Context) ([worktreeHashSaltLength]byte, error) {
	var result [worktreeHashSaltLength]byte
	salt, err := d.queries.GetWorktreeHashSalt(ctx)
	if err != nil {
		return result, fmt.Errorf("clientstate: read worktree hash salt: %w", err)
	}
	if len(salt) == 0 {
		generated := make([]byte, worktreeHashSaltLength)
		if _, err := rand.Read(generated); err != nil {
			return result, fmt.Errorf("clientstate: generate worktree hash salt: %w", err)
		}
		if err := d.queries.SetWorktreeHashSalt(ctx, generated); err != nil {
			return result, fmt.Errorf("clientstate: save worktree hash salt: %w", err)
		}
		salt, err = d.queries.GetWorktreeHashSalt(ctx)
		if err != nil {
			return result, fmt.Errorf("clientstate: reread worktree hash salt: %w", err)
		}
	}
	if len(salt) != worktreeHashSaltLength {
		return result, errors.New("clientstate: worktree hash salt is invalid")
	}
	copy(result[:], salt)
	return result, nil
}
