package publisher

import (
	"context"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

// dial bounds target setup and closes the raw socket when target TLS fails.
// the HTTP stream owns a successfully secured connection through cleanup.
func (target ServiceHTTPTarget) dial(ctx context.Context) (net.Conn, error) {
	if target.enter != nil {
		finish, ok := target.enter()
		if !ok {
			return nil, ErrEndpoint
		}
		defer finish()
	}
	if target.native != nil {
		life, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		stop := context.AfterFunc(target.lifetime, func() { defer close(done); cancel() })
		defer func() {
			cancel()
			if !stop() {
				<-done
			}
		}()
		ctx = life
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if target.native != nil {
		if err := nativeCheck(ctx, target.native); err != nil {
			return nil, err
		}
	}
	conn, err := observability.DialTarget(setup, "tcp", target.Address)
	if err != nil {
		return nil, err
	}
	if target.track != nil {
		target.track(conn)
	}
	if target.native != nil {
		if err := nativeCheck(ctx, target.native); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = &nativeServiceConn{conn: conn, ctx: target.lifetime, admission: target.native}
	}
	secured, err := target.Transport.Secure(setup, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if target.native != nil {
		if err := nativeCheck(ctx, target.native); err != nil {
			_ = secured.Close()
			return nil, err
		}
		secured = &nativeServiceConn{conn: secured, ctx: target.lifetime, admission: target.native}
	}
	return secured, nil
}
