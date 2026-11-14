package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ProjectDNSLabel is the readable source label captured when a project first
// claims a managed namespace. checkout paths and branches are not identities.
func ProjectDNSLabel(repository, directory string) string {
	value := repository
	if directory != "" && directory != "." {
		value += "-" + directory
	}
	var b strings.Builder
	separator := false
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if separator && b.Len() != 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			separator = false
		} else {
			separator = true
		}
	}
	label := b.String()
	if label == "" {
		return "project"
	}
	if len(label) <= 63 {
		return label
	}
	// retain readable prefixes and distinguish long monorepo paths after fitting.
	digest := sha256.Sum256([]byte(label))
	return strings.TrimRight(label[:50], "-") + "-" + hex.EncodeToString(digest[:6])
}

// DeploymentNamespace stays beneath an existing team or member namespace.
// the caller reserves it for one deployment ID.
func DeploymentNamespace(deployment, project, owner string) (string, error) {
	if !ValidServiceName(deployment) || deployment == "local" || project == "" || len(project) > 63 || strings.Contains(project, ".") {
		return "", errors.New("deployment namespace requires canonical deployment and project labels")
	}
	canonical, err := CanonicalizeHostname(project)
	if err != nil || canonical != project {
		return "", errors.New("managed project label is not canonical")
	}
	namespace := deployment + "." + project + "." + owner
	canonical, err = CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace || len("_acme-challenge."+namespace) > 253 || len("*."+namespace) > 253 {
		return "", errors.New("deployment namespace exceeds DNS bounds")
	}
	return namespace, nil
}
