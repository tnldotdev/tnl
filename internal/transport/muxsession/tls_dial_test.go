package muxsession

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type byteDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d *byteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func TestTLSYamuxInjectedTCPRetainsCertificateVerification(t *testing.T) {
	for _, name := range []string{"relay.test", "wrong.test"} {
		t.Run(name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			accepted := make(chan Session, 1)
			go func() {
				session, _ := AcceptTLSYamux(ctx, server, serverTLS, TLSYamuxConfig{})
				accepted <- session
			}()
			calls := 0
			connector := TLSYamuxConnector{TLSConfig: clientTLS, Config: TLSYamuxConfig{Dialer: &byteDialer{dial: func(call context.Context, network, address string) (net.Conn, error) {
				calls++
				if call != ctx || network != "tcp" || address != "host-byte-socket:443" {
					t.Error("injected dial lost its context or endpoint")
				}
				return client, nil
			}}}}
			session, err := connector.Connect(ctx, Endpoint{Address: "host-byte-socket:443", ServerName: name})
			if name == "relay.test" {
				if err != nil {
					t.Fatal(err)
				}
				_ = session.Close()
			} else if err == nil {
				_ = session.Close()
				t.Fatal("injected byte dial bypassed hostname verification")
			}
			if serverSession := <-accepted; serverSession != nil {
				_ = serverSession.Close()
			}
			if calls != 1 {
				t.Fatalf("dial calls = %d", calls)
			}
		})
	}
}

func TestTLSYamuxInjectedDialErrorIsPreserved(t *testing.T) {
	_, trust := testTLSConfigs(t)
	want := errors.New("host socket refused")
	_, err := (TLSYamuxConnector{TLSConfig: trust, Config: TLSYamuxConfig{Dialer: &byteDialer{dial: func(context.Context, string, string) (net.Conn, error) { return nil, want }}}}).Connect(t.Context(), Endpoint{Address: "relay.test:443", ServerName: "relay.test"})
	if !errors.Is(err, want) {
		t.Fatalf("dial error = %v", err)
	}
}

func TestTLSYamuxConnectorRemainsComparable(t *testing.T) {
	for _, config := range []TLSYamuxConfig{{}, {Dialer: new(net.Dialer)}, {Dialer: &byteDialer{}}} {
		var connector Connector = TLSYamuxConnector{Config: config}
		retained := connector
		if connector != retained {
			t.Fatal("retained connector changed identity")
		}
	}
}
