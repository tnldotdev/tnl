package naming

import (
	"net/url"
	"strings"
)

// ValidRequestPath accepts a bounded same-origin request path, including a query
// but never a fragment, absolute URL, or header-control bytes.
func ValidRequestPath(value string) bool {
	if len(value) < 1 || len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\x00\r\n#") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/")
}
