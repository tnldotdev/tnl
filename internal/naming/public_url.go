package naming

import (
	"errors"
	"strings"
)

// ParseExactPublicURL accepts a canonical hostname or its HTTPS origin.
// callers use the hostname for comparisons and add https:// for display.
func ParseExactPublicURL(value string) (string, error) {
	hostname := strings.TrimPrefix(value, "https://")
	canonical, err := CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || !strings.Contains(hostname, ".") {
		return "", errors.New("public URL must be a canonical hostname or HTTPS origin without a port, path, query, or fragment")
	}
	return hostname, nil
}
