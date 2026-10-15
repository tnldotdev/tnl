// Package routebackend defines how ingress opens a visitor stream to a publisher.
package routebackend

import (
	"context"
	"net"
)

// Backend opens one visitor stream through an assigned publisher connection.
type Backend interface {
	// Open uses the visitor connection ID to set up a stream that the caller must
	// close. it must not send PROXY metadata or visitor data; ingress sends those
	// bytes and owns the retry boundary. an error can occur after the relay accepts
	// the stream, for example when its acknowledgment is lost.
	Open(ctx context.Context, visitorConnectionID string) (net.Conn, error)
}

// PendingBackend opens a visitor stream with bounded authorization capacity.
// the publisher may complete visitor TLS and check credentials, but must never
// forward a request before promotion. ingress drops pending connections if
// a backend does not implement this interface.
type PendingBackend interface {
	Backend
	OpenPending(context.Context, string) (net.Conn, error)
}
