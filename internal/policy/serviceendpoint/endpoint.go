// package serviceendpoint validates service address facts shared by control,
// publishers, connectors, and project metadata. it owns no allocation or workers.
package serviceendpoint

import (
	"net"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

// valid binds the protocol to its transport endpoint. HTTP always uses 443,
// including connector-only identities; Public alone enables ingress access.
// a logical HTTP port never consumes an exclusive ingress port reservation.
func Valid(protocol, hostname string, port int, public bool) bool {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || hostname != canonical {
		return false
	}
	switch protocol {
	case "http":
		return port == 443
	case "tcp", "postgres", "mysql", "kubernetes":
		return port >= 1024 && port <= 65535 || port == 0 && !public
	default:
		return false
	}
}

// PermissionPort binds visitor permission to the service, not its optional
// ingress reservation. HTTP also uses this identity for browser origins.
func PermissionPort(protocol string) uint16 {
	if protocol == "http" {
		return 443
	}
	return 0
}

// HTTPAuthority is the canonical browser authority, not a connector dial address.
func HTTPAuthority(hostname string, port uint16) string {
	if port == 443 {
		return hostname
	}
	return net.JoinHostPort(hostname, strconv.Itoa(int(port)))
}

// MatchesHTTPAuthority permits hostname case differences, not trailing-dot or
// port aliases. the caller's canonical service identity remains unchanged.
func MatchesHTTPAuthority(hostname string, port uint16, authority string) bool {
	host, rawPort, hasPort := strings.Cut(authority, ":")
	canonical, err := naming.CanonicalizeHostname(host)
	if err != nil || strings.HasSuffix(host, ".") || canonical != hostname {
		return false
	}
	return !hasPort && port == 443 || hasPort && rawPort == strconv.Itoa(int(port))
}
