package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"net"
	"sync"
	"time"

	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func servePeerConnections(ctx, caller context.Context, config Config, prepared *preparedSelection, signer Signer, consume connectionConsumer, ready func(error)) error {
	p, err := preparePeerConnection(ctx, config, prepared, signer)
	if err != nil {
		if caller.Err() != nil {
			return nil
		}
		return err
	}
	defer p.Close()
	ready(nil)
	err = consume(p.ctx, func(ctx context.Context, local net.Conn) error {
		provider, err := p.open(ctx)
		if err != nil {
			return err // no stream is retried, even if its first write was uncertain.
		}
		defer provider.Close()
		if local == nil {
			if config.Protocol == "tcp" {
				return nil
			}
			verification := config.ServiceTLS.Clone()
			verification.ServerName = config.Endpoint.Hostname
			return (targettransport.Transport{Protocol: serviceconfig.ProtocolName(config.Protocol), TLS: verification}).PreflightConnection(ctx, provider)
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = provider.Close(); close(closed) })
		defer func() {
			if !stop() {
				<-closed
			}
		}()
		_, err = streamcopy.Copy(local, provider)
		return err
	})
	if caller.Err() != nil {
		return nil
	}
	if p.ctx.Err() != nil {
		return context.Cause(p.ctx)
	}
	return err
}

func (p *peerConnection) open(ctx context.Context) (_ net.Conn, retErr error) {
	ctx, finish := observability.Start(ctx, "connector.visitor_setup")
	defer func() { finish(retErr) }()
	run, binding, err := p.prepared.peerPreparedRun()
	if err != nil || !samePeerDelivery(p.initial, binding) || p.ctx.Err() != nil || ctx.Err() != nil {
		return nil, ErrServiceConnection
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stopOwner := context.AfterFunc(p.ctx, cancel)
	defer stopOwner()
	stream, err := p.session.OpenStream(setup)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = stream.Close()
		}
	}()
	deadline, _ := setup.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(setup, func() { _ = stream.SetDeadline(time.Now()); close(interrupted) })
	finishSetup := sync.OnceFunc(func() {
		if !stop() {
			<-interrupted
		}
	})
	defer finishSetup()
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return nil, err
	}
	entry := tunnelv1.NativePeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.NativePeerVisitorStream,
		PairID: binding.pair.PairId, DeliveryID: binding.pair.DeliveryId, DeliveryGeneration: binding.pair.DeliveryGeneration,
		ServiceID: run.ServiceID, ServiceRunID: run.ServiceRunID, RunNumber: run.RunNumber, Subject: p.signer.Subject,
		SourceIP: p.source, VisitorConnectionID: visitor, MetadataRevision: uint64(run.TrustRevision)}
	opening := func(initial []byte) error {
		permission, err := peerPermission(p.signer, entry, run.Permission.VisitorToken, initial)
		if err != nil {
			return err
		}
		entry.Permission = permission
		_, err = tunnelv1.WriteNativePeerVisitorOpening(stream, entry, initial)
		return err
	}
	var writer *tunnel.NativeRequestWriter
	if run.Protocol == "tcp" {
		writer = tunnel.NewNativeOpeningWriter(stream, opening)
	} else {
		if err := opening(nil); err != nil {
			return nil, err
		}
		writer = tunnel.NewNativeRequestWriter(stream)
	}
	var result net.Conn = writer
	if run.Protocol == "tcp" {
		verification := run.ServiceTLS.Clone()
		verification.ServerName = run.Endpoint.Hostname
		verification.MinVersion = max(verification.MinVersion, tls.VersionTLS12)
		secure := tls.Client(writer, verification)
		if err := secure.HandshakeContext(setup); err != nil {
			return nil, err
		}
		result = secure
	}
	finishSetup()
	if setup.Err() != nil || p.ctx.Err() != nil {
		return nil, ErrServiceConnection
	}
	if _, err := p.prepared.peerRunForRenewal(binding); err != nil {
		return nil, err
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	current := func() (Run, error) { return p.prepared.peerRunForRenewal(p.initial) }
	renew := renewPreparedPermission(ctx, stream, writer, current, run, func(token string) (tunnelv1.NativeVisitorPermission, error) {
		return peerPermission(p.signer, entry, token, nil)
	})
	return &privateConn{Conn: result, writer: writer, release: func() {}, stop: renew}, nil
}

func peerPermission(signer Signer, entry tunnelv1.NativePeerVisitorEntry, token string, initial []byte) (tunnelv1.NativeVisitorPermission, error) {
	entry.Permission = tunnelv1.NativeVisitorPermission{Token: token, PublicKey: base64.RawURLEncoding.EncodeToString(signer.PublicKey),
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	message, err := tunnelv1.NativePeerProofMessage(entry, initial)
	if err != nil || signer.Sign == nil {
		return tunnelv1.NativeVisitorPermission{}, ErrServiceConnection
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return tunnelv1.NativeVisitorPermission{}, ErrServiceConnection
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return entry.Permission, nil
}
