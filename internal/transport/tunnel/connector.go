package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ConnectorSession retains the authenticated control stream so both
// QUIC and TLS/TCP use the same enrolled-device handshake and byte streams.
type ConnectorSession struct {
	muxsession.Session
	Accepted tunnelv1.ConnectorSessionAccepted
	control  muxsession.Stream
}

func DialConnector(ctx context.Context, transport muxsession.Session, hello tunnelv1.ConnectorSessionHello) (result *ConnectorSession, err error) {
	if transport == nil {
		return nil, errors.New("tunnel: private transport is required")
	}
	defer func() {
		if err != nil {
			_ = transport.Close()
		}
	}()
	stream, err := transport.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
		}
	}()
	if err = tunnelv1.WriteConnectorSessionHello(stream, hello); err != nil {
		return nil, err
	}
	accepted, err := tunnelv1.ReadConnectorSessionAccepted(stream)
	if err != nil {
		return nil, err
	}
	if accepted.ServiceID != hello.ServiceID || accepted.SessionID != hello.SessionID ||
		accepted.Subject != hello.Subject || !accepted.ExpiresAt.After(time.Now()) {
		return nil, errors.New("tunnel: private connector acceptance changed identity")
	}
	return &ConnectorSession{Session: transport, Accepted: accepted, control: stream}, nil
}

type ConnectorAuthenticate func(context.Context, tunnelv1.ConnectorSessionHello) (tunnelv1.ConnectorSessionAccepted, error)

func AcceptConnector(ctx context.Context, transport muxsession.Session, authenticate ConnectorAuthenticate) (result *ConnectorSession, err error) {
	if transport == nil || authenticate == nil {
		return nil, errors.New("tunnel: private transport and authenticator are required")
	}
	defer func() {
		if err != nil {
			_ = transport.Close()
		}
	}()
	setup, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	stream, err := transport.AcceptStream(setup)
	if err != nil {
		return nil, err
	}
	finish, err := setupDeadline(setup, stream)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
		}
	}()
	hello, err := tunnelv1.ReadConnectorSessionHello(stream)
	if err != nil {
		return nil, err
	}
	accepted, err := authenticate(setup, hello)
	if err != nil {
		return nil, err
	}
	if accepted.SessionID != hello.SessionID || accepted.ServiceID != hello.ServiceID || accepted.Subject != hello.Subject || !accepted.ExpiresAt.After(time.Now()) {
		return nil, errors.New("tunnel: private connector authenticator changed identity")
	}
	if err = tunnelv1.WriteConnectorSessionAccepted(stream, accepted); err != nil {
		return nil, err
	}
	return &ConnectorSession{Session: transport, Accepted: accepted, control: stream}, nil
}
