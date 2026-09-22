package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressExactSNIHandoffs(t *testing.T) {
	for _, test := range []struct {
		name, hostname, alpn string
		challenge            bool
	}{
		{"control", "control.example", "", false},
		{"relay", "relay.example", "tnl-tunnel/1", false},
		{"relay challenge", "relay.example", "acme-tls/1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			connections := make(chan net.Conn)
			handoff := func(c net.Conn) bool {
				select {
				case connections <- c:
					return true
				case <-ctx.Done():
					return false
				}
			}
			var wrong atomic.Int32
			config := Config{}
			if test.name == "control" {
				config.ServerHostname = test.hostname
				config.HandleControl = handoff
			} else {
				config.RelayHostname = test.hostname
				if test.challenge {
					config.HandleRelayChallenge = handoff
					config.HandleRelay = func(net.Conn) bool { wrong.Add(1); return false }
				} else {
					config.HandleRelay = handoff
				}
			}
			_, address := startIngress(t, config)
			certificate := testCertificate(t, test.hostname)
			result := ingressWorker(t, cancel, func() error {
				var c net.Conn
				select {
				case c = <-connections:
				case <-ctx.Done():
					return ctx.Err()
				}
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stop()
				_ = c.SetDeadline(time.Now().Add(fixtureTimeout))
				secured := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{test.alpn}})
				if err := secured.Handshake(); err != nil {
					return err
				}
				if !c.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
					return errors.New("lost visitor address")
				}
				if test.challenge {
					return nil
				}
				var request [4]byte
				if _, err := io.ReadFull(secured, request[:]); err != nil {
					return err
				}
				if string(request[:]) != "ping" {
					return errors.New("unexpected handoff payload")
				}
				_, err := secured.Write([]byte("pong"))
				return err
			})
			var protos []string
			if test.alpn != "" {
				protos = []string{test.alpn}
			}
			client := ingressClient(t, address, strings.ToUpper(test.hostname), "", protos...)
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if test.challenge {
				_ = client.Close()
			} else {
				exchangePing(t, client)
			}
			if err := ingressAwait(t, result); err != nil {
				t.Fatal(err)
			}
			if wrong.Load() != 0 {
				t.Fatal("ACME reached publisher transport handler")
			}
			// Matching must be exact, not a suffix match.
			other := ingressClient(t, address, "other."+test.hostname, "", protos...)
			if err := other.Handshake(); err == nil {
				t.Fatal("handoff accepted a different hostname")
			}
		})
	}
}

func TestIngressHandoffsHaveIndependentCapacityHeldUntilClose(t *testing.T) {
	for _, test := range []struct {
		name, hostname string
		configure      func(*Config, func(net.Conn) bool)
	}{
		{"control", "control.example", func(config *Config, handoff func(net.Conn) bool) {
			config.ServerHostname, config.HandleControl = "control.example", handoff
		}},
		{"relay", "relay.example", func(config *Config, handoff func(net.Conn) bool) {
			config.RelayHostname, config.HandleRelay = "relay.example", handoff
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handled := make(chan net.Conn, 2)
			metrics := new(testMetrics)
			config := Config{SourceConnectionRate: 0.000001, SourceConnectionBurst: 1, Metrics: metrics,
				MaxControlConnections: 1, MaxRelayConnections: 1}
			test.configure(&config, func(connection net.Conn) bool {
				handled <- connection
				return true
			})
			server, address := startIngress(t, config)
			// Exhaust the same visitor source bucket first.
			ordinary := ingressClient(t, address, "route.example", "")
			_ = ordinary.Handshake()
			_ = ordinary.Close()
			ordinary = ingressClient(t, address, "route.example", "")
			_ = ordinary.Handshake()
			_ = ordinary.Close()
			if metrics.sourceLimiterRejections.Load() != 1 {
				t.Fatal("ordinary source bucket was not exhausted")
			}
			client := ingressClient(t, address, test.hostname, "")
			handshake := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
			owned := ingressAwait(t, handled)
			t.Cleanup(func() { _ = owned.Close() })
			blocked := ingressClient(t, address, test.hostname, "")
			if err := blocked.Handshake(); err == nil {
				t.Fatal("service capacity was not enforced")
			}
			_ = blocked.Close()
			select {
			case <-handled:
				t.Fatal("handoff slot released before its owner closed the connection")
			default:
			}
			_ = owned.Close()
			_ = owned.Close() // Closing twice must release the slot only once.
			_ = ingressAwait(t, handshake)
			next := ingressClient(t, address, test.hostname, "")
			nextHandshake := ingressWorker(t, func() { _ = next.Close() }, next.Handshake)
			nextOwned := ingressAwait(t, handled)
			_ = nextOwned.Close()
			_ = ingressAwait(t, nextHandshake)
			if server.limiter.Entries() != 1 || metrics.sourceLimiterRejections.Load() != 1 {
				t.Fatalf("source limiter entries=%d rejections=%d", server.limiter.Entries(), metrics.sourceLimiterRejections.Load())
			}
		})
	}
}
