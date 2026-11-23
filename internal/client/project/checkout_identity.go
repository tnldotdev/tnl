package project

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Git moves the checkout but preserves its private administration directory.
// clones, and newly added worktrees at the same path, get a new directory.
func (p Project) checkoutKey(ctx context.Context) (string, error) {
	if !p.Worktree.IsGit {
		return "", nil
	}
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--absolute-git-dir")
	cmd.Dir = p.Worktree.Root
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("read Git checkout identity directory: %w", err)
	}
	dir := strings.TrimSuffix(string(output), "\n")
	if !filepath.IsAbs(dir) {
		return "", errors.New("checkout identity directory from Git is not absolute")
	}
	id, err := readOrCreateCheckoutID(dir)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(p.Root)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(p.Worktree.Root, root)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(append(id, 0), filepath.ToSlash(relative)...))
	return hex.EncodeToString(digest[:]), nil
}

func readOrCreateCheckoutID(dir string) ([]byte, error) {
	path := filepath.Join(dir, "tnl-checkout")
	id, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		temp, createErr := os.CreateTemp(dir, ".tnl-checkout-")
		if createErr != nil {
			return nil, createErr
		}
		defer os.Remove(temp.Name())
		_, writeErr := temp.Write(random[:])
		if err := errors.Join(writeErr, temp.Close()); err != nil {
			return nil, err
		}
		// link the complete file into place without replacing a concurrent winner.
		if err := os.Link(temp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		id, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if len(id) != 32 {
		return nil, errors.New("invalid tnl checkout identity")
	}
	return id, nil
}
