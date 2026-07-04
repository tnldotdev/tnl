package config

import (
	"context"
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

// ResolveWorktree returns stable project facts and falls back to cwd when Git
// is unavailable or cwd is not inside a worktree.
func ResolveWorktree(ctx context.Context, cwd string) (Worktree, error) {
	absolute, err := filepath.Abs(cwd)
	if err != nil {
		return Worktree{}, err
	}
	root := filepath.Clean(absolute)
	isGit := false
	command := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	command.Dir = root
	if output, commandErr := command.Output(); commandErr == nil {
		discovered := strings.TrimSpace(string(output))
		if discoveredRoot, pathErr := filepath.Abs(discovered); discovered != "" && pathErr == nil && pathWithin(root, discoveredRoot) {
			root = filepath.Clean(discoveredRoot)
			isGit = true
		}
	}
	name := filepath.Base(root)
	if name == "" || name == string(filepath.Separator) || name == "." {
		name = "worktree"
	}
	return Worktree{Root: root, Name: name, Label: WorktreeLabel(name, root), IsGit: isGit}, nil
}

func WorktreeLabel(name, root string) string {
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
	if len(stem) > 56 {
		stem = strings.TrimRight(stem[:56], "-")
	}
	if stem == "" {
		stem = "worktree"
	}
	digest := sha256.Sum256([]byte(root))
	return stem + "-" + hex.EncodeToString(digest[:3])
}

// ValidServiceName reports whether value is a canonical service DNS label.
func ValidServiceName(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return true
}

// ServiceWorktreeLabel returns the built-in hostname label for one service.
func ServiceWorktreeLabel(service, worktreeLabel string) string {
	if service == "" {
		return worktreeLabel
	}
	maximumWorktreeLength := 63 - len(service) - 1
	if len(worktreeLabel) > maximumWorktreeLength {
		digest := worktreeLabel[len(worktreeLabel)-7:]
		stem := strings.TrimRight(worktreeLabel[:maximumWorktreeLength-7], "-")
		worktreeLabel = stem + digest
	}
	return service + "-" + worktreeLabel
}
