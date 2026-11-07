package config

import (
	"regexp"
	"strings"
)

var vercelProjectName = regexp.MustCompile(`^[a-z0-9._-]{1,100}$`)

// ValidVercelProjectName checks project names, which are not dns labels.
func ValidVercelProjectName(name string) bool {
	return vercelProjectName.MatchString(name) && !strings.Contains(name, "---")
}
