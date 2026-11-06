package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// postgresTLS owns SSLRequest and verified visitor TLS on the same admitted
// stream. it never sends a startup message or application credentials.
func postgresTLS(parent context.Context, raw net.Conn, trust *tls.Config) (_ *tls.Conn, result error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() { defer close(closed); _ = raw.Close() })
	stopped := false
	defer func() {
		if result != nil {
			_ = raw.Close()
			cause := context.Cause(ctx)
			if deadline, ok := ctx.Deadline(); cause == nil && ok && !time.Now().Before(deadline) {
				cause = context.DeadlineExceeded
			}
			result = errors.Join(result, cause)
		}
		if !stopped && !stopClose() {
			<-closed
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := raw.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
		return nil, err
	}
	var response [1]byte
	if _, err := io.ReadFull(raw, response[:]); err != nil {
		return nil, err
	}
	if response[0] != 'S' {
		return nil, errors.New("connector WASM: postgres refused visitor TLS")
	}
	secure := tls.Client(raw, trust)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) || !stopClose() {
		return nil, errors.Join(net.ErrClosed, context.Cause(ctx))
	}
	stopped = true
	return secure, nil
}
