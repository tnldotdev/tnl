package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

// Serve owns target transports for exactly one admitted HTTP visitor. routing and
// response hooks stay in the existing proxy; every dial retains this stream's
// connector checks and physical cleanup rather than borrowing another visitor's
// socket. the caller's wrapper runs before target resolution or forwarding.
func (target HTTPTarget) Serve(ctx context.Context, client net.Conn, hostname string, wrap func(http.Handler) http.Handler, hooks httpstream.ResponseHooks) (result error) {
	if client == nil || wrap == nil {
		return ErrEndpoint
	}
	if target.Handler != nil {
		if target.Address != "" || target.Transport.TLS != nil || len(target.Mounts) != 0 || target.ResolveTarget != nil {
			return ErrEndpoint
		}
		return httpstream.ServeHandler(ctx, client, wrap(target.Handler), target.Drain)
	}
	if target.Transport.Protocol != config.ProtocolHTTP {
		return ErrEndpoint
	}
	scheme := "http"
	options := proxy.TargetOptions{}
	if target.Transport.TLS != nil {
		scheme = "https"
		options.RootCAs, options.ServerName = target.Transport.TLS.RootCAs, target.Transport.TLS.ServerName
	}
	const connections = 64
	forwarder, err := proxy.New(proxy.Config{
		Hostname: hostname, Target: (&url.URL{Scheme: scheme, Host: target.Address}).String(),
		TargetOptions: options, Mounts: target.Mounts, ResolveTarget: target.ResolveTarget,
		Hooks: hooks, MaxConnsPerHost: connections,
		Transport: func(location *url.URL, options proxy.TargetOptions, base bool) (proxy.Transport, error) {
			selected := target
			selected.Address = location.Host
			if base {
				if (location.Scheme == "https") != (target.Transport.TLS != nil) {
					return nil, ErrEndpoint
				}
				if target.Transport.TLS != nil {
					selected.Transport.TLS = target.Transport.TLS.Clone()
				}
			} else if location.Scheme == "https" {
				name := options.ServerName
				if name == "" {
					name = location.Hostname()
				}
				selected.Transport.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs, ServerName: name}
			} else {
				selected.Transport.TLS = nil
			}
			if err := selected.Transport.Validate(); err != nil {
				return nil, err
			}
			return httpstream.NewTargetTransport(ctx, selected.Dial, connections)
		},
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, forwarder.Close()) }()
	return httpstream.ServeHandler(ctx, client, wrap(http.HandlerFunc(forwarder.ServeAdmittedHTTP)), target.Drain)
}

// Dial bounds target setup and closes the raw socket when target TLS fails.
// the HTTP stream owns a successfully secured connection through cleanup.
func (target HTTPTarget) Dial(ctx context.Context) (net.Conn, error) {
	if target.enter != nil {
		finish, ok := target.enter()
		if !ok {
			return nil, ErrEndpoint
		}
		defer finish()
	}
	if target.lifetime != nil {
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
	if target.connector != nil {
		if err := connectorCheck(ctx, target.connector); err != nil {
			return nil, err
		}
	}
	conn, err := observability.DialTarget(setup, "tcp", target.Address)
	if err != nil {
		return nil, err
	}
	if target.track != nil {
		conn = target.track(conn)
	}
	if target.connector != nil {
		if err := connectorCheck(ctx, target.connector); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		conn = &connectorServiceConn{conn: conn, ctx: target.lifetime, admission: target.connector}
	}
	secured, err := target.Transport.Secure(setup, conn)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if target.connector != nil {
		if err := connectorCheck(ctx, target.connector); err != nil {
			return nil, errors.Join(err, secured.Close())
		}
		if target.Transport.TLS != nil {
			secured = &connectorServiceConn{conn: secured, ctx: target.lifetime, admission: target.connector}
		}
	}
	return secured, nil
}

// targetSocket retains physical cleanup without retaining sockets already closed
// by a completed request. half-close remains available for non-HTTP protocols.
type targetSocket struct {
	net.Conn
	once   sync.Once
	remove func()
	err    error
}

func (c *targetSocket) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.remove()
	})
	return c.err
}

func (c *targetSocket) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}
