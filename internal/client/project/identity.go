package project

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

// SourceIdentity is independent of checkout directory, branch and client state.
// the full fingerprint lets control reject a project-key collision.
type SourceIdentity struct {
	Key         string
	Fingerprint string
	Label       string
	Source      naming.GitProjectSource
}

// LocalPublicationIdentity identifies configured development services in this
// canonical project directory. Git initialization, origin changes and branches
// do not change it. it is not a portable source identity for apply or workloads.
type LocalPublicationIdentity struct {
	Key         string
	Fingerprint string
}

func (p Project) LocalPublicationIdentity() LocalPublicationIdentity {
	digest := sha256.Sum256([]byte("tnl-local-publication-v1\x00" + p.Root))
	fingerprint := hex.EncodeToString(digest[:])
	return LocalPublicationIdentity{Key: "local-" + fingerprint[:48], Fingerprint: fingerprint}
}

// LocalWorktreeKey identifies this project directory without sending local paths
// to control. server, team and source identity remain separate scope checks.
func (p Project) LocalWorktreeKey() string {
	digest := sha256.Sum256([]byte("tnl-local-worktree-v1\x00" + p.Root))
	return hex.EncodeToString(digest[:])
}

func (p Project) SourceIdentity(ctx context.Context) (SourceIdentity, error) {
	if !p.Found() || !p.Worktree.IsGit {
		return SourceIdentity{}, errors.New("apply requires a project configuration in a Git repository with an origin remote")
	}
	command := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	command.Dir = p.Worktree.Root
	output, err := command.Output()
	if err != nil {
		return SourceIdentity{}, errors.New("read Git origin for project identity; configure origin before applying")
	}
	relative, err := filepath.Rel(p.Worktree.Root, p.Selection.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return SourceIdentity{}, errors.New("project configuration must be inside the Git repository")
	}
	origin, err := naming.SanitizeGitRemote(string(output))
	if err != nil {
		return SourceIdentity{}, err
	}
	source := naming.GitProjectSource{GitOrigin: origin, ConfigurationPath: filepath.ToSlash(relative)}
	identity, err := source.Identity()
	if err != nil {
		return SourceIdentity{}, err
	}
	return SourceIdentity{Key: identity.Key, Fingerprint: identity.Fingerprint, Label: identity.Label, Source: source}, nil
}

// GitHubRepository infers only github.com origins. source identity remains a
// separate checkout-independent contract and never carries job credentials.
func (p Project) GitHubRepository(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	command.Dir = p.Worktree.Root
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read workload GitHub origin: %w", err)
	}
	remote, err := naming.NormalizeGitRemote(string(output))
	if err != nil {
		return "", err
	}
	repository, ok := strings.CutPrefix(remote, "github.com/")
	if !ok || len(strings.Split(repository, "/")) != 2 {
		return "", errors.New("workload repository inference requires a github.com origin; set workloads.NAME.github.repository explicitly")
	}
	return repository, nil
}
