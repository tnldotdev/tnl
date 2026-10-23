// Package routebackend defines how ingress opens a visitor stream to a publisher.
package backend

import (
	"context"
	"net"
)

// Backend opens one visitor stream through an assigned publisher connection.
type Backend interface {
	// Open uses the visitor connection ID to set up a stream that the caller must
	// close. it must not send PROXY metadata or visitor data; ingress sends those
	// bytes and owns the retry boundary. network acceptance or rejection is
	// consumed on return-side reads, before any response byte reaches the visitor.
	Open(ctx context.Context, visitorConnectionID string) (net.Conn, error)
}

// StartingBackend sends routing metadata, the trusted PROXY v2 header, and the
// buffered visitor bytes in one opening. an error must retain whether visitor
// bytes crossed the retry boundary. ordinary in-process byte backends can use
// Open instead; network forwarding uses this capability.
type StartingBackend interface {
	Backend
	Start(context.Context, string, bool, []byte, []byte) (net.Conn, error)
}

// PendingBackend opens a visitor stream with bounded authorization capacity.
// the publisher may complete visitor TLS and check credentials, but must never
// forward a request before promotion. ingress drops pending connections if
// a backend does not implement this interface.
type PendingBackend interface {
	Backend
	OpenPending(context.Context, string) (net.Conn, error)
}
