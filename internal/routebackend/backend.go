// Package routebackend defines how ingress opens a visitor stream to a publisher.
package routebackend

import (
	"context"
	"net"
)

// Backend opens one byte stream for a visitor connection to a publisher route.
type Backend interface {
	// Open uses the visitor connection ID to set up a stream that the caller must
	// close. It must not send PROXY metadata or visitor data; ingress sends those
	// bytes and owns the retry boundary. An error can occur after the relay accepts
	// the stream, for example when its acknowledgment is lost.
	Open(ctx context.Context, visitorConnectionID string) (net.Conn, error)
}
