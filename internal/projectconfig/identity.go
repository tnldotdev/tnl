package projectconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os/exec"
	"path"
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
}

// LocalWorktreeKey identifies this project directory without sending local paths
// to control. server, team and source identity remain separate scope checks.
func (p Project) LocalWorktreeKey() string {
	digest := sha256.Sum256([]byte("tnl-local-worktree-v1\x00" + p.Worktree.Root + "\x00" + p.Root))
	return hex.EncodeToString(digest[:])
}

func NormalizeGitRemote(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		colon := strings.IndexByte(value, ':')
		if colon <= 0 || strings.ContainsAny(value[:colon], "/\\") {
			return "", errors.New("apply requires a network Git origin; local filesystem remotes are not portable")
		}
		value = "ssh://" + value[:colon] + "/" + value[colon+1:]
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("apply requires a network Git origin without query parameters or fragments")
	}
	switch u.Scheme {
	case "ssh", "git", "http", "https":
	default:
		return "", errors.New("apply requires an ssh, git, http or https Git origin")
	}
	host := strings.ToLower(u.Hostname())
	defaultPort := map[string]string{"ssh": "22", "https": "443", "http": "80", "git": "9418"}[u.Scheme]
	if port := u.Port(); port != "" && port != defaultPort {
		host += ":" + port
	}
	repository := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	if repository == "" || repository == "/" || path.Clean(repository) != repository || strings.ContainsAny(repository, "\\\x00\r\n") {
		return "", errors.New("git origin must name one repository")
	}
	// transport and login user do not change repository ownership.
	return host + "/" + strings.TrimPrefix(repository, "/"), nil
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
	remote, err := NormalizeGitRemote(string(output))
	if err != nil {
		return SourceIdentity{}, err
	}
	relative, err := filepath.Rel(p.Worktree.Root, p.Selection.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return SourceIdentity{}, errors.New("project configuration must be inside the Git repository")
	}
	digest := sha256.Sum256([]byte("tnl-project-source-v1\x00" + remote + "\x00" + filepath.ToSlash(relative)))
	fingerprint := hex.EncodeToString(digest[:])
	label := naming.ProjectDNSLabel(path.Base(remote), filepath.ToSlash(filepath.Dir(relative)))
	return SourceIdentity{Key: "project-" + fingerprint[:48], Fingerprint: fingerprint, Label: label}, nil
}
