// package tcpconnect carries a visitor's local TCP connection over verified
// visitor TLS. it does not own client state, URL selection, or a background job.
package tcpconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tcpport"
)

var ErrInvalidConnection = errors.New("invalid visitor TCP connection settings")

type Options struct {
	PublicURLID string
	Hostname    string
	Port        int
	Certificate tls.Certificate
	// ALPN must be negotiated exactly when specified. an empty value uses the
	// existing TCP visitor TLS contract, which does not negotiate ALPN.
	ALPN    string
	RootCAs *x509.CertPool // nil uses the system WebPKI roots.
}

// Listen accepts only a numeric loopback address and a TCP port. port zero
// lets the OS choose a free local port; callers must report the chosen address.
func Listen(address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, parseErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || parseErr != nil || n < 0 || n > tcpport.Max || port != strconv.Itoa(n) {
		return nil, ErrInvalidConnection
	}
	return net.Listen("tcp", net.JoinHostPort(ip.String(), port))
}

func (o Options) validate() error {
	host, err := naming.CanonicalizeHostname(o.Hostname)
	leaf := o.Certificate.Leaf
	if leaf == nil || len(leaf.URIs) != 1 {
		return ErrInvalidConnection
	}
	scope := leaf.URIs[0]
	identity, bound := strings.CutPrefix(scope.Path, "/"+o.PublicURLID+"/")
	if err != nil || host != o.Hostname || net.ParseIP(host) != nil || !opaqueid.Valid(o.PublicURLID, opaqueid.PublicURLPrefix) || !tcpport.Valid(o.Port) ||
		len(o.Certificate.Certificate) == 0 || o.Certificate.PrivateKey == nil || !bound || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) ||
		scope.Scheme != "tnl" || scope.Host != "visitor" || scope.User != nil || scope.RawPath != "" || scope.RawQuery != "" || scope.Fragment != "" || scope.Opaque != "" ||
		time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) ||
		len(o.ALPN) > 255 {
		return ErrInvalidConnection
	}
	return nil
}

// Connect authenticates the WebPKI server and the URL-bound in-memory visitor
// certificate before copying any application bytes. both directions use fixed
// 32 KiB buffers; EOF from the local client half-closes the TLS write side.
// cancellation closes both sockets and joins their copy workers.
func Connect(ctx context.Context, o Options, local net.Conn) error {
	if local == nil {
		return ErrInvalidConnection
	}
	defer local.Close()
	if err := o.validate(); err != nil {
		return err
	}
	// callers cannot turn this adapter into a proxy for a nonlocal client.
	localAddress, localOK := local.LocalAddr().(*net.TCPAddr)
	peerAddress, peerOK := local.RemoteAddr().(*net.TCPAddr)
	if !localOK || !peerOK || !localAddress.IP.IsLoopback() || !peerAddress.IP.IsLoopback() {
		return ErrInvalidConnection
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: o.Hostname, RootCAs: o.RootCAs, Certificates: []tls.Certificate{o.Certificate}}
	if o.ALPN != "" {
		config.NextProtos = []string{o.ALPN}
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: config}
	address := net.JoinHostPort(o.Hostname, strconv.Itoa(o.Port))
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dialer.DialContext(handshake, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect visitor TLS: %w", err)
	}
	remote := raw.(*tls.Conn)
	defer remote.Close()
	if o.ALPN != "" && remote.ConnectionState().NegotiatedProtocol != o.ALPN {
		return ErrInvalidConnection
	}
	stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = remote.Close() })
	defer stop()
	sent, received := make(chan error, 1), make(chan error, 1)
	done := ctx.Done()
	go func() {
		_, err := io.CopyBuffer(remote, local, make([]byte, 32<<10))
		if err == nil {
			err = remote.CloseWrite()
		}
		sent <- err
	}()
	go func() {
		_, err := io.CopyBuffer(local, remote, make([]byte, 32<<10))
		if err == nil {
			if tcp, ok := local.(*net.TCPConn); ok {
				err = tcp.CloseWrite()
			}
		}
		received <- err
	}()
	var first error
	for sent != nil || received != nil {
		select {
		case err := <-sent:
			if err != nil && first == nil {
				first = err
				_ = local.Close()
				_ = remote.Close()
			}
			sent = nil
		case err := <-received:
			if err != nil && first == nil {
				first = err
				_ = local.Close()
				_ = remote.Close()
			}
			received = nil
		case <-done:
			_ = local.Close()
			_ = remote.Close()
			done = nil
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first != nil {
		return fmt.Errorf("copy visitor TCP stream: %w", first)
	}
	return nil
}
