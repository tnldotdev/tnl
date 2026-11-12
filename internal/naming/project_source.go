package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"path"
	"strings"
)

// GitProjectSource identifies a configuration without checkout paths or content hashes.
type GitProjectSource struct {
	GitOrigin         string `json:"git_origin"`
	ConfigurationPath string `json:"configuration_path"`
}

type ProjectSourceIdentity struct {
	Key, Fingerprint, Label string
}

func (s GitProjectSource) Identity() (ProjectSourceIdentity, error) {
	remote, err := NormalizeGitRemote(s.GitOrigin)
	relative := s.ConfigurationPath
	if err != nil || len(s.GitOrigin) > 4096 || len(relative) > 4096 || relative == "" || relative == "." || path.IsAbs(relative) || path.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, "\\\x00\r\n") {
		return ProjectSourceIdentity{}, errors.New("project source requires a network Git origin and repository-relative configuration path")
	}
	digest := sha256.Sum256([]byte("tnl-project-source-v1\x00" + remote + "\x00" + relative))
	fingerprint := hex.EncodeToString(digest[:])
	return ProjectSourceIdentity{Key: "project-" + fingerprint[:48], Fingerprint: fingerprint, Label: ProjectDNSLabel(path.Base(remote), path.Dir(relative))}, nil
}

// SanitizeGitRemote keeps source facts portable without forwarding git credentials.
func SanitizeGitRemote(value string) (string, error) {
	u, err := gitRemoteURL(value)
	if err != nil {
		return "", err
	}
	u.User = nil
	return u.String(), nil
}

func gitRemoteURL(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		colon := strings.IndexByte(value, ':')
		if colon <= 0 || strings.ContainsAny(value[:colon], "/\\") {
			return nil, errors.New("apply requires a network Git origin; local filesystem remotes are not portable")
		}
		value = "ssh://" + value[:colon] + "/" + value[colon+1:]
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("apply requires a network Git origin without query parameters or fragments")
	}
	switch u.Scheme {
	case "ssh", "git", "http", "https":
	default:
		return nil, errors.New("apply requires an ssh, git, http or https Git origin")
	}
	return u, nil
}

func NormalizeGitRemote(value string) (string, error) {
	u, err := gitRemoteURL(value)
	if err != nil {
		return "", err
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
