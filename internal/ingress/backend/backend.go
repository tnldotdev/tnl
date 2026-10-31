// Package backend defines how ingress opens a visitor stream to a publisher.
package backend

import (
	"context"
	"net"
)

// Backend opens one visitor stream through an assigned publisher connection.
type Backend interface {
	// Start sends the opening metadata and initial visitor prefix exactly once.
	// it owns failed streams and returns nil on error. failures after any visitor
	// byte must retain tunnel.OpeningError, including partial writes.
	// pending visitors have bounded authorization capacity until promotion.
	Start(ctx context.Context, visitorConnectionID string, pending bool, proxy, initial []byte) (net.Conn, error)
}
