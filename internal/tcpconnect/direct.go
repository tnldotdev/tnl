package tcpconnect

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/streamcopy"
)

// opaque clients such as OpenSSH need a local TLS helper on the public path.
// native HTTPS and database clients negotiate their own TLS without this helper.
func serveDirectTCP(ctx context.Context, listen *net.TCPAddr, config Config, consume connectionConsumer) error {
	if config.ServiceTLS == nil || config.ServiceTLS.InsecureSkipVerify || config.ManagedTLS == nil || !config.ManagedTLS.Public || config.Protocol != "tcp" {
		return ErrPrivateConnection
	}
	serveCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	return consume(serveCtx, func(connectionCtx context.Context, local net.Conn) error {
		selection, finish := context.WithTimeout(connectionCtx, 10*time.Second)
		run, err := config.Control.ResolvePrivateService(selection, config.PrivateServiceID)
		finish()
		if err != nil {
			return err
		}
		if run.PrivateServiceID != config.PrivateServiceID {
			return ErrPrivateConnection
		}
		if run.Protocol != config.Protocol || run.TrustRevision != config.TrustRevision || !sameManagedTLS(run.ManagedTLS, config.ManagedTLS) {
			err := metadataReload(config.PrivateServiceID, config.TrustRevision, run.TrustRevision)
			cancel(err)
			return err
		}
		verification := config.ServiceTLS.Clone()
		verification.ServerName = config.ManagedTLS.Hostname
		verification.MinVersion = max(verification.MinVersion, tls.VersionTLS12)
		address := net.JoinHostPort(config.ManagedTLS.Hostname, strconv.Itoa(config.ManagedTLS.Port))
		handshake, finish := context.WithTimeout(connectionCtx, 10*time.Second)
		dialer := &net.Dialer{Timeout: 10 * time.Second, ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			host, port, err := net.SplitHostPort(address)
			if err != nil || listen != nil && net.ParseIP(host).Equal(listen.IP) && port == strconv.Itoa(listen.Port) {
				// a cached loopback DNS answer must not recursively dial this
				// helper while the endpoint is becoming publicly reachable.
				return ErrPrivateConnection
			}
			return nil
		}}
		upstream, err := (&tls.Dialer{NetDialer: dialer, Config: verification}).DialContext(handshake, "tcp", address)
		finish()
		if err != nil {
			return err
		}
		defer upstream.Close()
		stop := context.AfterFunc(connectionCtx, func() { _ = local.Close(); _ = upstream.Close() })
		defer stop()
		_, err = streamcopy.Copy(local, upstream)
		return err
	})
}
