package tcpconnect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPublicOpaqueHelperUsesDirectMTLSWithoutConnectorAssignments(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		t.Run(strconv.FormatBool(authenticated), func(t *testing.T) {
			ca, certificate := testCertificateForUses(t, []string{"localhost"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("invalid fixture roots")
			}
			public, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer public.Close()
			const request, response = "SSH-2.0-native-client\r\n", "SSH-2.0-existing-target\r\n"
			serverDone := make(chan error, 1)
			go func() {
				connection, err := public.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				payload := make([]byte, len(request))
				_, err = io.ReadFull(connection, payload)
				if err == nil && !bytes.Equal(payload, []byte(request)) {
					err = ErrPrivateConnection
				}
				if err == nil {
					_, err = io.WriteString(connection, response)
				}
				serverDone <- err
			}()
			local, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			endpoint := &controlv1.ManagedServiceTLS{Hostname: "localhost", Port: public.Addr().(*net.TCPAddr).Port, Public: true}
			service, identity := connectorID(t, opaqueid.PrivateServicePrefix), connectorID(t, opaqueid.IdentityPrefix)
			control := &connectorFixture{run: Run{PrivateServiceID: service, Protocol: "tcp", TrustRevision: 1, ManagedTLS: endpoint}}
			verification := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			if authenticated {
				verification.Certificates = []tls.Certificate{certificate}
			}
			ctx, cancel := context.WithCancel(t.Context())
			ready, done := make(chan struct{}), make(chan error, 1)
			go func() {
				done <- Serve(ctx, local, Config{Control: control, PrivateServiceID: service, IdentityID: identity, Protocol: "tcp", TrustRevision: 1, ManagedTLS: endpoint, ServiceTLS: verification, Ready: func() error { close(ready); return nil }})
			}()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			select {
			case <-ready:
			case err := <-done:
				done <- err
				t.Fatal("helper did not start", err)
			case <-time.After(3 * time.Second):
				t.Fatal("helper did not report listener readiness")
			}
			client, err := net.DialTimeout("tcp", local.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.WriteString(client, request)
			payload := make([]byte, len(response))
			_, err = io.ReadFull(client, payload)
			serverErr := <-serverDone
			if authenticated && (err != nil || serverErr != nil || string(payload) != response) || !authenticated && (err == nil || serverErr == nil) {
				t.Fatal("direct mTLS boundary did not protect opaque bytes", err, serverErr)
			}
			if control.assignments[0].Load()+control.assignments[1].Load() != 0 {
				t.Fatal("public helper allocated private connector sessions")
			}
		})
	}
}

func TestPublicHelperRejectsItsOwnCachedLoopbackEndpoint(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	endpoint := &controlv1.ManagedServiceTLS{Hostname: "localhost", Port: local.Addr().(*net.TCPAddr).Port, Public: true}
	service, identity := connectorID(t, opaqueid.PrivateServicePrefix), connectorID(t, opaqueid.IdentityPrefix)
	control := &connectorFixture{run: Run{PrivateServiceID: service, Protocol: "tcp", TrustRevision: 1, ManagedTLS: endpoint}}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- Serve(ctx, local, Config{Control: control, PrivateServiceID: service, IdentityID: identity, Protocol: "tcp", TrustRevision: 1, ManagedTLS: endpoint, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS12}, Ready: func() error { close(ready); return nil }})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("helper did not start", err)
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not report listener readiness")
	}
	client, err := net.DialTimeout("tcp", local.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err = client.Read(value[:]); err == nil {
		t.Fatal("helper connected to itself")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("cached loopback DNS recursively stalled the helper")
	}
}

func TestPublicHelperReloadsPrivacyBeforeDialing(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	endpoint := &controlv1.ManagedServiceTLS{Hostname: "localhost", Port: 25443, Public: true}
	private := *endpoint
	private.Public = false
	service, identity := connectorID(t, opaqueid.PrivateServicePrefix), connectorID(t, opaqueid.IdentityPrefix)
	control := &connectorFixture{run: Run{PrivateServiceID: service, Protocol: "tcp", TrustRevision: 1, ManagedTLS: &private}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- Serve(ctx, local, Config{Control: control, PrivateServiceID: service, IdentityID: identity, Protocol: "tcp", TrustRevision: 1, ManagedTLS: endpoint, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS12}, Ready: func() error { close(ready); return nil }})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("helper did not start", err)
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not report readiness")
	}
	client, err := net.DialTimeout("tcp", local.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-done:
		if !IsMetadataReload(err) {
			t.Fatal("privacy changed without refreshing the runner", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("public helper kept serving after privacy changed")
	}
}
