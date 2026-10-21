package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PrivateConnectorSession retains the authenticated control stream so both
// QUIC and TLS/TCP use the same enrolled-device handshake and byte streams.
type PrivateConnectorSession struct {
	muxsession.Session
	Accepted tunnelv1.PrivateConnectorSessionAccepted
	control  muxsession.Stream
}

func DialPrivateConnector(ctx context.Context, transport muxsession.Session, hello tunnelv1.PrivateConnectorSessionHello) (result *PrivateConnectorSession, err error) {
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
	if err = tunnelv1.WritePrivateConnectorSessionHello(stream, hello); err != nil {
		return nil, err
	}
	accepted, err := tunnelv1.ReadPrivateConnectorSessionAccepted(stream)
	if err != nil {
		return nil, err
	}
	if accepted.PrivateServiceID != hello.PrivateServiceID || accepted.SessionID != hello.SessionID ||
		accepted.Subject != hello.Subject || !accepted.ExpiresAt.After(time.Now()) {
		return nil, errors.New("tunnel: private connector acceptance changed identity")
	}
	return &PrivateConnectorSession{Session: transport, Accepted: accepted, control: stream}, nil
}

type PrivateConnectorAuthenticate func(context.Context, tunnelv1.PrivateConnectorSessionHello) (tunnelv1.PrivateConnectorSessionAccepted, error)

func AcceptPrivateConnector(ctx context.Context, transport muxsession.Session, authenticate PrivateConnectorAuthenticate) (result *PrivateConnectorSession, err error) {
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
	hello, err := tunnelv1.ReadPrivateConnectorSessionHello(stream)
	if err != nil {
		return nil, err
	}
	accepted, err := authenticate(setup, hello)
	if err != nil {
		return nil, err
	}
	if accepted.SessionID != hello.SessionID || accepted.PrivateServiceID != hello.PrivateServiceID || accepted.Subject != hello.Subject || !accepted.ExpiresAt.After(time.Now()) {
		return nil, errors.New("tunnel: private connector authenticator changed identity")
	}
	if err = tunnelv1.WritePrivateConnectorSessionAccepted(stream, accepted); err != nil {
		return nil, err
	}
	return &PrivateConnectorSession{Session: transport, Accepted: accepted, control: stream}, nil
}
