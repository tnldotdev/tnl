// package targettransport owns publisher-to-target negotiation. visitor TLS is
// independent; a nil target verifier selects plaintext, never unverified TLS.
package targettransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

var ErrTargetTLS = errors.New("target TLS negotiation failed")

// Transport selects negotiation by the application protocol, not the visitor's
// handshake. verification is always ordinary certificate and hostname checking.
type Transport struct {
	Protocol config.ProtocolName
	TLS      *tls.Config
}

func (t Transport) Validate() error {
	if !t.Protocol.Valid() || t.TLS != nil && (t.TLS.InsecureSkipVerify || t.TLS.ServerName == "" || t.TLS.VerifyConnection != nil || t.TLS.VerifyPeerCertificate != nil) {
		return failure.Wrap("validate target transport", failure.InvalidTarget, ErrTargetTLS)
	}
	return nil
}

func (t Transport) Secure(ctx context.Context, backend net.Conn) (net.Conn, error) {
	if err := t.Validate(); err != nil {
		return backend, err
	}
	if t.TLS == nil {
		return backend, nil
	}
	if t.Protocol == config.ProtocolMySQL {
		// MySQL is server-first. callers forwarding a real client must use its
		// bounded SSLRequest after reading this connection's greeting exactly once.
		return backend, rejected(ErrTargetTLS)
	}
	if t.Protocol == config.ProtocolPostgres {
		if _, err := backend.Write(PostgresSSLRequest[:]); err != nil {
			return backend, err
		}
		var accepted [1]byte
		if _, err := io.ReadFull(backend, accepted[:]); err != nil {
			return backend, err
		}
		if accepted[0] != 'S' {
			return backend, rejected(ErrDatabaseTLS)
		}
	}
	return t.Handshake(ctx, backend)
}

// Handshake starts TLS only after the caller has finished native negotiation.
func (t Transport) Handshake(ctx context.Context, backend net.Conn) (net.Conn, error) {
	if err := t.Validate(); err != nil || t.TLS == nil {
		return backend, errors.Join(ErrTargetTLS, err)
	}
	verification := t.TLS.Clone()
	verification.MinVersion = max(verification.MinVersion, tls.VersionTLS12)
	verification.NextProtos = nil
	if t.Protocol == config.ProtocolHTTP {
		verification.NextProtos = []string{"http/1.1"}
	}
	secured := tls.Client(backend, verification)
	if err := secured.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return backend, context.Cause(ctx)
		}
		var certificate *tls.CertificateVerificationError
		var record tls.RecordHeaderError
		if errors.As(err, &certificate) || errors.As(err, &record) {
			return backend, rejected(err)
		}
		return backend, failure.Wrap("negotiate target TLS", failure.TargetUnavailable, errors.Join(ErrTargetTLS, err))
	}
	return secured, nil
}

// Preflight opens a disposable connection and sends no login or application
// bytes. MySQL reads the greeting before its SSLRequest; it is never HTTPS.
func (t Transport) Preflight(ctx context.Context, address string) (result error) {
	if err := t.Validate(); err != nil {
		return err
	}
	setup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			result = context.Cause(ctx)
		}
	}()
	backend, err := (&net.Dialer{}).DialContext(setup, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return failure.Wrap("connect to target", failure.TargetUnavailable, err)
	}
	defer backend.Close()
	stop := context.AfterFunc(setup, func() { _ = backend.Close() })
	defer stop()
	deadline, _ := setup.Deadline()
	if err := backend.SetDeadline(deadline); err != nil {
		return err
	}
	if t.TLS == nil {
		return nil
	}
	if t.Protocol == config.ProtocolMySQL {
		greeting, err := ReadMySQLPacket(backend, 64<<10)
		if err != nil {
			if errors.Is(err, ErrDatabaseTLS) {
				return rejected(err)
			}
			return failure.Wrap("read MySQL greeting", failure.TargetUnavailable, err)
		}
		request, err := MySQLSSLRequest(greeting)
		if err != nil {
			return rejected(err)
		}
		if _, err := backend.Write(request); err != nil {
			return err
		}
		_, err = t.Handshake(setup, backend)
		return err
	}
	_, err = t.Secure(setup, backend)
	return err
}

func rejected(err error) error {
	return failure.Wrap("verify target TLS", failure.TargetTLSRejected, errors.Join(ErrTargetTLS, err))
}
