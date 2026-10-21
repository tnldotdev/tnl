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
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

type backend struct {
	expires    time.Time
	ca         string
	port       int
	streamPort int
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
func (b *backend) Close(context.Context) error              { return nil }

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	parent, err := filepath.EvalSymlinks(os.Args[1])
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
	expires := time.Now().Add(5 * time.Minute)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "database.example.test"}, DNSNames: []string{"database.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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
	go echo(stream, nil)
	go echo(listener, tlsConfig)
	scope := connectionruntime.Context{Schema: 1, Directory: parent, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example.test", Audience: "https://control.example.test", ProjectKey: "project", SourceID: "source", WorktreeKey: "worktree", Services: []string{"database", "stream"}}
	b := &backend{expires: expires, ca: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), port: listener.Addr().(*net.TCPAddr).Port, streamPort: stream.Addr().(*net.TCPAddr).Port}
	return connectionruntime.Serve(ctx, scope, directory, os.Args[2], b, os.Stdout)
}

func echo(listener net.Listener, tlsConfig *tls.Config) {
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
			_, _ = io.CopyN(conn, conn, 4)
		}(conn)
	}
}
