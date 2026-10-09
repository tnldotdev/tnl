package projectconfig

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type Worktree struct {
	Root  string        `json:"root"`
	Name  string        `json:"name"`
	Label WorktreeLabel `json:"label"`
	IsGit bool          `json:"isGit"`

	primaryRoot string
	labelParts  worktreeLabelParts
}

// PrimaryCheckoutRoot returns the primary Git checkout shared by linked worktrees.
func (w Worktree) PrimaryCheckoutRoot() string {
	if w.primaryRoot != "" {
		return w.primaryRoot
	}
	return w.Root
}

// WorktreeLabel exposes the DNS-safe pieces used in the finished label.
// the primary checkout has no checkout component.
type WorktreeLabel struct {
	Project   string `json:"project"`
	Checkout  string `json:"checkout,omitempty"`
	ID        string `json:"id"`
	FullLabel string `json:"fullLabel"`
}

type worktreeLabelParts struct {
	project  string
	checkout string
	id       string
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
	if canonical, err := filepath.EvalSymlinks(root); err == nil {
		root = canonical
	}
	isGit := false
	if err := ctx.Err(); err != nil {
		return Worktree{}, err
	}
	command := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	command.Dir = root
	if output, commandErr := command.Output(); commandErr == nil {
		discovered := strings.TrimSuffix(string(output), "\n")
		if discoveredRoot, pathErr := filepath.Abs(discovered); discovered != "" && pathErr == nil {
			if canonical, err := filepath.EvalSymlinks(discoveredRoot); err == nil {
				discoveredRoot = canonical
			}
			if pathWithin(root, discoveredRoot) {
				root = filepath.Clean(discoveredRoot)
				isGit = true
			}
		}
	} else if err := ctx.Err(); err != nil {
		return Worktree{}, err
	}
	primaryRoot := root
	if isGit {
		primaryRoot, err = primaryGitWorktree(ctx, root)
		if err != nil {
			return Worktree{}, err
		}
	}
	name := filepath.Base(root)
	if name == "" || name == string(filepath.Separator) || name == "." {
		name = "worktree"
	}
	return Worktree{Root: root, Name: name, IsGit: isGit, primaryRoot: primaryRoot}, nil
}

func primaryGitWorktree(ctx context.Context, root string) (string, error) {
	command := exec.CommandContext(ctx, "git", "worktree", "list", "--porcelain", "-z")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return "", cause
		}
		return "", fmt.Errorf("list Git worktrees: %w", err)
	}
	line, _, _ := bytes.Cut(output, []byte{0})
	path, ok := bytes.CutPrefix(line, []byte("worktree "))
	if !ok || len(path) == 0 || !filepath.IsAbs(string(path)) {
		return "", errors.New("list Git worktrees: missing primary worktree")
	}
	primary := filepath.Clean(string(path))
	if canonical, err := filepath.EvalSymlinks(primary); err == nil {
		primary = canonical
	}
	return primary, nil
}

func ApplyWorktreeHashSalt(worktree Worktree, projectRoot string, salt [32]byte) Worktree {
	if canonical, err := filepath.EvalSymlinks(projectRoot); err == nil {
		projectRoot = canonical
	}
	project := worktree.Name
	if worktree.primaryRoot != "" {
		project = filepath.Base(worktree.primaryRoot)
	}
	if project == "." || project == string(filepath.Separator) || project == "" {
		project = "project"
	}
	if projectRoot != worktree.Root && worktree.IsGit {
		relative, err := filepath.Rel(worktree.Root, projectRoot)
		if err == nil && relative != "." && pathWithin(projectRoot, worktree.Root) {
			project += "-" + filepath.ToSlash(relative)
		}
	}
	parts := worktreeLabelParts{project: dnsLabelStem(project, "project"), id: worktreeLabelID(worktree.Root, projectRoot, salt)}
	if worktree.IsGit && worktree.Root != worktree.primaryRoot {
		parts.checkout = dnsLabelStem(worktree.Name, "worktree")
	}
	worktree.labelParts = parts
	fitted := fitWorktreeLabel("", parts)
	worktree.Label = WorktreeLabel{Project: fitted.project, Checkout: fitted.checkout, ID: fitted.id, FullLabel: formatWorktreeLabel("", fitted)}
	return worktree
}

func worktreeLabelID(root, projectRoot string, salt [32]byte) string {
	return labelID("tnl-worktree-label-v2\x00", root, projectRoot, salt)
}

func labelID(purpose, root, projectRoot string, salt [32]byte) string {
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(purpose))
	_, _ = hash.Write([]byte(root))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(projectRoot))
	sum := hash.Sum(nil)
	value := binary.BigEndian.Uint32(sum[:4]) >> 1
	encoded := strconv.FormatUint(uint64(value), 36)
	return strings.Repeat("0", 6-len(encoded)) + encoded
}

func dnsLabelStem(value, fallback string) string {
	var normalized strings.Builder
	separator := false
	for _, character := range norm.NFKD.String(strings.ToLower(value)) {
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
	if normalized.Len() == 0 {
		return fallback
	}
	return normalized.String()
}

func fitWorktreeLabel(service string, parts worktreeLabelParts) worktreeLabelParts {
	remaining := 63 - len(parts.id) - 1
	if service != "" {
		remaining -= len(service) + 1
	}
	project, checkout := parts.project, parts.checkout
	if checkout == "" {
		project = strings.TrimRight(project[:min(len(project), remaining)], "-")
	} else if len(project)+len(checkout)+1 > remaining {
		// give each name room before using any spare bytes for the longer one.
		available := remaining - 1
		projectBudget := min(len(project), available/2)
		checkoutBudget := min(len(checkout), available-projectBudget)
		projectBudget = min(len(project), available-checkoutBudget)
		project = strings.TrimRight(project[:projectBudget], "-")
		checkout = strings.TrimRight(checkout[:checkoutBudget], "-")
	}
	return worktreeLabelParts{project: project, checkout: checkout, id: parts.id}
}

func formatWorktreeLabel(service string, parts worktreeLabelParts) string {
	parts = fitWorktreeLabel(service, parts)
	project := parts.project
	if parts.checkout != "" {
		project += "-" + parts.checkout
	}
	if service != "" {
		project = service + "-" + project
	}
	return project + "-" + parts.id
}

// ServiceWorktreeLabel returns the built-in hostname label for one service.
func ServiceWorktreeLabel(service string, worktree Worktree) string {
	return formatWorktreeLabel(service, worktree.labelParts)
}

// SharedProjectLabel gives linked worktrees one label for project integration URLs.
func SharedProjectLabel(role string, worktree Worktree, projectRoot string, salt [32]byte) string {
	primary, relative := sharedProjectPath(worktree, projectRoot)
	name := filepath.Base(primary)
	if relative != "." {
		name += "-" + filepath.ToSlash(relative)
	}
	identity := filepath.Join(primary, relative)
	var id string
	switch role {
	case "hooks":
		hash := hmac.New(sha256.New, salt[:])
		_, _ = hash.Write([]byte("tnl-shared-project-webhook-label-v2\x00"))
		_, _ = hash.Write([]byte(primary))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(identity))
		id = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash.Sum(nil)[:8]))
	case "oauth":
		id = labelID("tnl-shared-project-oauth-label-v2\x00", primary, identity, salt)
	default:
		id = labelID("tnl-shared-project-label-v1\x00", primary, identity, salt)
	}
	parts := worktreeLabelParts{project: dnsLabelStem(name, "project"), id: id}
	return formatWorktreeLabel(role, parts)
}

// SharedProjectIdentity is the checkout-independent local state key.
func SharedProjectIdentity(worktree Worktree, projectRoot string) string {
	primary, relative := sharedProjectPath(worktree, projectRoot)
	return filepath.Join(primary, relative)
}

func sharedProjectPath(worktree Worktree, projectRoot string) (string, string) {
	if canonical, err := filepath.EvalSymlinks(projectRoot); err == nil {
		projectRoot = canonical
	}
	primary := worktree.primaryRoot
	if primary == "" {
		primary = worktree.Root
	}
	relative, err := filepath.Rel(worktree.Root, projectRoot)
	if err != nil || !pathWithin(projectRoot, worktree.Root) {
		relative = "."
	}
	return primary, relative
}
