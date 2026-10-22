package naming

import (
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
	return b.String()
}

// ManagedGroupNamespace stays beneath an existing team or member namespace.
// the caller reserves the result against its immutable group identity.
func ManagedGroupNamespace(group, project, owner string) (string, error) {
	if !ValidServiceName(group) || group == "local" || project == "" || len(project) > 63 || strings.Contains(project, ".") {
		return "", errors.New("managed group requires a canonical group and project label")
	}
	canonical, err := CanonicalizeHostname(project)
	if err != nil || canonical != project {
		return "", errors.New("managed project label is not canonical")
	}
	namespace := group + "." + project + "." + owner
	canonical, err = CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace || len("_acme-challenge."+namespace) > 253 || len("*."+namespace) > 253 {
		return "", errors.New("managed group namespace exceeds DNS bounds")
	}
	return namespace, nil
}
