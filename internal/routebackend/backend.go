// Package routebackend defines the transport-neutral ingress-to-publisher boundary.
package routebackend

import (
	"context"
	"net"
)

// Backend opens one byte stream for a visitor connection to a publisher route.
type Backend interface {
	// Open correlates setup with the visitor connection ID and returns a stream
	// the caller must close. It must not send PROXY metadata or visitor payload;
	// ingress owns those bytes and the retry boundary. An error may follow remote
	// admission (for example a lost acknowledgment), not necessarily zero work.
	Open(ctx context.Context, visitorConnectionID string) (net.Conn, error)
}
