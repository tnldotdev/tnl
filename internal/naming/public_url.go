package naming

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

// HTTPSOrigin renders an exact endpoint, never a local listener or default port.
// an unreserved or invalid endpoint has no public origin.
func HTTPSOrigin(hostname string, port int) string {
	canonical, err := CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || !tcpport.ValidNetwork(port) {
		return ""
	}
	return "https://" + net.JoinHostPort(hostname, strconv.Itoa(port))
}

// ParseExactPublicURL accepts a canonical hostname or its HTTPS origin.
// this selects a name before allocation, not a reserved public endpoint.
func ParseExactPublicURL(value string) (string, error) {
	hostname := strings.TrimPrefix(value, "https://")
	canonical, err := CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || !strings.Contains(hostname, ".") {
		return "", errors.New("public URL must be a canonical hostname or HTTPS origin without a port, path, query, or fragment")
	}
	return hostname, nil
}
