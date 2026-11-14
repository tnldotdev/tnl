// package serviceendpoint validates service address facts shared by control,
// publishers, connectors, and project metadata. it owns no allocation or workers.
package serviceendpoint

import (
	"net"
	"strconv"

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

// HTTPAuthority is the canonical browser authority, not a connector dial address.
func HTTPAuthority(hostname string, port uint16) string {
	if port == 443 {
		return hostname
	}
	return net.JoinHostPort(hostname, strconv.Itoa(int(port)))
}

func MatchesHTTPAuthority(hostname string, port uint16, authority string) bool {
	return authority == HTTPAuthority(hostname, port) ||
		port == 443 && authority == net.JoinHostPort(hostname, "443")
}
