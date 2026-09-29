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

// DenialBackend opens a separate visitor stream marked as IP-policy denied.
// The publisher may complete visitor TLS to send a 403, but must never forward
// a denied request to the local service. Ingress drops denied connections if
// a backend does not implement this interface.
type DenialBackend interface {
	Backend
	OpenDenied(context.Context, string) (net.Conn, error)
}
