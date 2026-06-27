// Package routebackend defines the transport-neutral ingress-to-publisher boundary.
package routebackend

import (
	"context"
	"net"
)

// Backend opens one byte stream for a visitor connection to a publisher route.
type Backend interface {
	Open(context.Context, string) (net.Conn, error)
}
