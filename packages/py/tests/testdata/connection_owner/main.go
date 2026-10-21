// this fixture exercises the real native owner and CLI, not a Python transport.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

type backend struct {
	expires    time.Time
	ca         string
	port       int
	streamPort int
	listeners  []net.Listener
}

func (b *backend) Start(context.Context) (projectmeta.PublicMetadata, time.Time, error) {
	service, err := projectmeta.NewEndpoint("example.test", "database.example.test", "postgres", 15443, false)
	stream, streamErr := projectmeta.NewEndpoint("example.test", "stream.example.test", "tcp", 15444, false)
	if err == nil {
		err = streamErr
	}
	return projectmeta.PublicMetadata{Namespace: "example.test", Services: map[string]projectmeta.Service{"database": service, "stream": stream}}, b.expires, err
}
func (b *backend) Connect(_ context.Context, service string) (connectionruntime.Connection, error) {
	if service == "stream" {
		return connectionruntime.Connection{Schema: 1, Protocol: "tcp", Host: "127.0.0.1", Port: b.streamPort, ExpiresAt: b.expires}, nil
	}
	if service != "database" {
		return connectionruntime.Connection{}, connectionruntime.ErrInvalid
	}
	return connectionruntime.Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: b.port, SSL: &connectionruntime.TLSOptions{ServerName: "database.example.test", RejectUnauthorized: true, CA: b.ca}, ExpiresAt: b.expires}, nil
}
func (b *backend) Renew(context.Context) (time.Time, error) { return b.expires, nil }
func (b *backend) Prepared(service string) (connectionruntime.Connection, error) {
	return b.Connect(context.Background(), service)
}
func (b *backend) Close(context.Context) error {
	var result error
	for _, listener := range b.listeners {
		result = errors.Join(result, listener.Close())
	}
	return result
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("connection_owner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lifetime := flags.Duration("tnl-lifetime", 5*time.Minute, "owner deadline")
	listenAddress := flags.String("tnl-listen-address", "127.0.0.1:0", "loopback listener")
	postgresAuth := flags.Bool("tnl-postgres-auth", false, "serve a minimal PostgreSQL password handshake")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listenAddress)
	if flags.NArg() != 2 || *lifetime < time.Second || *lifetime > 5*time.Minute || err != nil || host != "127.0.0.1" {
		return errors.New("invalid fixture arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	parent, err := filepath.EvalSymlinks(flags.Arg(0))
	if err != nil {
		return err
	}
	directory, err := connectionruntime.NewDirectory(parent)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	expires := time.Now().Add(*lifetime)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "database.example.test"}, DNSNames: []string{"database.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	stream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer stream.Close()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	go echo(stream, nil, false)
	go echo(listener, tlsConfig, *postgresAuth)
	scope := connectionruntime.Context{Schema: 1, Directory: parent, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example.test", Audience: "https://control.example.test", ProjectKey: "project", SourceID: "source", WorktreeKey: "worktree", Services: []string{"database", "stream"}}
	b := &backend{expires: expires, ca: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), port: listener.Addr().(*net.TCPAddr).Port, streamPort: stream.Addr().(*net.TCPAddr).Port, listeners: []net.Listener{listener, stream}}
	return connectionruntime.Serve(ctx, scope, directory, flags.Arg(1), b, os.Stdout)
}

func echo(listener net.Listener, tlsConfig *tls.Config, postgresAuth bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if tlsConfig != nil {
				var request [8]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil || request != [8]byte{0, 0, 0, 8, 4, 210, 22, 47} {
					return
				}
				if _, err := conn.Write([]byte("S")); err != nil {
					return
				}
				conn = tls.Server(conn, tlsConfig)
			}
			if postgresAuth {
				postgresHandshake(conn)
				return
			}
			_, _ = io.CopyN(conn, conn, 4)
		}(conn)
	}
}

func postgresHandshake(conn net.Conn) {
	// qualify libpq's dial/SNI/trust options without pretending this fixture is
	// a database or the production publisher's SCRAM/channel-binding forwarder.
	backend := pgproto3.NewBackend(conn, conn)
	message, err := backend.ReceiveStartupMessage()
	if _, ok := message.(*pgproto3.StartupMessage); err != nil || !ok {
		return
	}
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if backend.Flush() != nil {
		return
	}
	message, err = backend.Receive()
	password, ok := message.(*pgproto3.PasswordMessage)
	if err != nil || !ok || password.Password != "fixture-password" {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if backend.Flush() != nil {
		return
	}
	_, _ = backend.Receive() // libpq Terminate after a successful connection.
}
