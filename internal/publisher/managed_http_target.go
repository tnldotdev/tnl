package publisher

import (
	"context"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

// dial bounds target setup and closes the raw socket when target TLS fails.
// the HTTP stream owns a successfully secured connection through cleanup.
func (target ManagedHTTPTarget) dial(ctx context.Context) (net.Conn, error) {
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := observability.DialTarget(setup, "tcp", target.Address)
	if err != nil {
		return nil, err
	}
	secured, err := target.Transport.Secure(setup, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secured, nil
}
