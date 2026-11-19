package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type terminalRelayTransport struct {
	muxsession.Session
	entered, release, ended chan struct{}
	terminal, read, cleanup error
	endOnce                 sync.Once
}

func (s *terminalRelayTransport) AcceptStream(context.Context) (muxsession.Stream, error) {
	close(s.entered)
	<-s.release
	return nil, errors.Join(s.terminal, s.read)
}

func (s *terminalRelayTransport) Done() <-chan struct{} { return s.ended }
func (s *terminalRelayTransport) Err() error {
	select {
	case <-s.ended:
		return s.terminal
	default:
		return nil
	}
}
func (s *terminalRelayTransport) Close() error {
	s.end()
	return errors.Join(s.Session.Close(), s.cleanup)
}

func (s *terminalRelayTransport) end() { s.endOnce.Do(func() { close(s.ended) }) }

type terminalRelayConnector struct {
	relayConnector
	once      sync.Once
	transport *terminalRelayTransport
}

func (c *terminalRelayConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	session, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	result := session
	c.once.Do(func() {
		c.transport.Session = session
		result = c.transport
	})
	return result, nil
}

func TestForwarderRetiresRemoteSessionFailureWithoutLosingCleanup(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		for _, kind := range []string{"session", "session_joins_on_close", "independent_read", "stream_cleanup", "transport_cleanup"} {
			t.Run(kind+map[bool]string{false: "", true: "/canceled"}[canceled], func(t *testing.T) {
				material := newForwardingTestMaterial(t)
				server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
					session, err := restorationAcceptIngress(ctx, transport)
					if err != nil {
						return err
					}
					defer session.Close()
					select {
					case <-session.Done():
					case <-ctx.Done():
					}
					return nil
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				reported := make(chan error, 1)
				forwarder, err := NewForwarder(ForwarderConfig{
					Context: ctx, TLSConfig: &tls.Config{RootCAs: material.roots},
					ClusterSecret: forwardingClusterSecret, QUIC: muxsession.DisabledConnector{},
					OnSessionClosed: func(_, _, _ string, cause error) { reported <- cause },
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = forwarder.Close() })
				lost := &quic.IdleTimeoutError{}
				independent := errors.New("independent owned failure")
				transport := &terminalRelayTransport{
					entered: make(chan struct{}), release: make(chan struct{}), ended: make(chan struct{}), terminal: lost,
				}
				switch kind {
				case "independent_read":
					transport.read = independent
				case "stream_cleanup":
					transport.read = &tunnel.SessionCleanupError{Err: lost}
				case "transport_cleanup":
					transport.cleanup = independent
				}
				release := sync.OnceFunc(func() { close(transport.release) })
				defer release()
				forwarder.connector = &terminalRelayConnector{relayConnector: forwarder.connector, transport: transport}
				target := relayTarget{address: server.address(), serverName: material.serverName, relayServiceID: "relay", relayID: "process", relayRunID: "run", relayLeaseRevision: 1}
				first, _, err := forwarder.session(ingressContext(t), target)
				if err != nil {
					t.Fatal(err)
				}
				ingressAwait(t, transport.entered)
				// quic-go can wake AcceptStream before publishing the same
				// terminal error on the connection context. Close joins it.
				if kind != "session_joins_on_close" {
					transport.end()
				}
				if canceled {
					cancel()
				}
				release()
				if cause := ingressAwait(t, reported); !errors.Is(cause, lost) {
					t.Fatal("session loss was not reported", cause)
				}
				if !canceled {
					next, reused, err := forwarder.session(ingressContext(t), target)
					if err != nil || reused || next == first {
						t.Fatal("failed session prevented a fresh authenticated connection", err, reused)
					}
				}
				err = forwarder.Close()
				switch kind {
				case "session", "session_joins_on_close":
					if err != nil {
						t.Fatal("recovered session failure poisoned joined close", err)
					}
				case "stream_cleanup":
					var cleanup *tunnel.SessionCleanupError
					if !errors.As(err, &cleanup) || !errors.Is(err, lost) {
						t.Fatal("session end hid a failed owned stream cleanup", err)
					}
				default:
					if !errors.Is(err, independent) {
						t.Fatal("session end hid an independent failure", err)
					}
				}
			})
		}
	}
}
