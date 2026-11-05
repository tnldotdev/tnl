//go:build !tnl_benchtrace

package publisher

import "net"

func serviceBenchTraceCopy(_ ServiceConnectorAdmission, client, target net.Conn) (net.Conn, net.Conn) {
	return client, target
}
