package sshclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
)

// ConnectOptions specifies a verified mutual TLS connection. nil RootCAs uses
// the system WebPKI roots; custom roots are useful for local boundary tests.
type ConnectOptions struct {
	Address     string
	ServerName  string
	Certificate tls.Certificate
	RootCAs     *x509.CertPool
}

// Connect carries raw stdio over verified TLS, using serverName for SNI and
// certificate verification and certificate for mutual TLS authentication.
func Connect(ctx context.Context, address, serverName string, certificate tls.Certificate, stdin io.Reader, stdout io.Writer) error {
	return ConnectWithOptions(ctx, ConnectOptions{Address: address, ServerName: serverName, Certificate: certificate}, stdin, stdout)
}

// ConnectWithOptions half-closes TLS writes at stdin EOF and drains the reply.
// cancellation and peer EOF close the network connection without waiting for
// blocked stdio. the caller owns stdin and stdout: an arbitrary reader or writer
// cannot be interrupted here, so its copy goroutine may outlive this call until
// the caller unblocks it. close caller-owned pipes after cancellation/return.
func ConnectWithOptions(ctx context.Context, options ConnectOptions, stdin io.Reader, stdout io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validHostname(options.ServerName) || net.ParseIP(options.ServerName) != nil ||
		len(options.Certificate.Certificate) == 0 || options.Certificate.PrivateKey == nil || stdin == nil || stdout == nil {
		return ErrInvalidSession
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   options.ServerName,
		RootCAs:      options.RootCAs,
		Certificates: []tls.Certificate{options.Certificate},
	}
	dialer := tls.Dialer{Config: config}
	raw, err := dialer.DialContext(ctx, "tcp", options.Address)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &Error{Op: "connect SSH TLS transport", Err: err}
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sent, received := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, stdin)
		if err == nil {
			err = conn.CloseWrite()
		}
		sent <- err
	}()
	go func() {
		_, err := io.Copy(stdout, conn)
		received <- err
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sent:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return &Error{Op: "send SSH TLS stream", Err: err}
			}
			// a successful stdin EOF is only a half-close, not session completion.
			sent = nil
		case err := <-received:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return &Error{Op: "receive SSH TLS stream", Err: err}
			}
			return nil
		}
	}
}
