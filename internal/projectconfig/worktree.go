package projectconfig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type Worktree struct {
	Root  string `json:"root"`
	Name  string `json:"name"`
	Label string `json:"label"`
	IsGit bool   `json:"isGit"`
}

// ResolveWorktree returns project facts and falls back to cwd when Git is
// unavailable or cwd is not inside a worktree. ApplyWorktreeHashSalt adds the
// client-state-specific label used in public hostnames.
func ResolveWorktree(ctx context.Context, cwd string) (Worktree, error) {
	absolute, err := filepath.Abs(cwd)
	if err != nil {
		return Worktree{}, err
	}
	root := filepath.Clean(absolute)
	isGit := false
	if err := ctx.Err(); err != nil {
		return Worktree{}, err
	}
	command := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	command.Dir = root
	if output, commandErr := command.Output(); commandErr == nil {
		discovered := strings.TrimSpace(string(output))
		if discoveredRoot, pathErr := filepath.Abs(discovered); discovered != "" && pathErr == nil && pathWithin(root, discoveredRoot) {
			root = filepath.Clean(discoveredRoot)
			isGit = true
		}
	} else if err := ctx.Err(); err != nil {
		return Worktree{}, err
	}
	name := filepath.Base(root)
	if name == "" || name == string(filepath.Separator) || name == "." {
		name = "worktree"
	}
	return Worktree{Root: root, Name: name, IsGit: isGit}, nil
}

func ApplyWorktreeHashSalt(worktree Worktree, salt [32]byte) Worktree {
	worktree.Label = WorktreeLabel(worktree.Name, worktree.Root, salt)
	return worktree
}

func WorktreeLabel(name, root string, salt [32]byte) string {
	var normalized strings.Builder
	separator := false
	for _, character := range norm.NFKD.String(strings.ToLower(name)) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			if separator && normalized.Len() != 0 {
				normalized.WriteByte('-')
			}
			normalized.WriteRune(character)
			separator = false
		} else {
			separator = true
		}
	}
	stem := strings.Trim(normalized.String(), "-")
	if len(stem) > 54 {
		stem = strings.TrimRight(stem[:54], "-")
	}
	if stem == "" {
		stem = "worktree"
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte("tnl-worktree-label-v1\x00"))
	_, _ = hash.Write([]byte(root))
	return stem + "-" + hex.EncodeToString(hash.Sum(nil)[:4])
}

// ServiceWorktreeLabel returns the built-in hostname label for one service.
func ServiceWorktreeLabel(service, worktreeLabel string) string {
	if service == "" {
		return worktreeLabel
	}
	maximumWorktreeLength := 63 - len(service) - 1
	if len(worktreeLabel) > maximumWorktreeLength {
		digest := worktreeLabel[len(worktreeLabel)-9:]
		stem := strings.TrimRight(worktreeLabel[:maximumWorktreeLength-9], "-")
		worktreeLabel = stem + digest
	}
	return service + "-" + worktreeLabel
}
