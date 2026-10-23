package service

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func (b *Bound) admitNative(ctx context.Context, stream net.Conn, header tunnelv1.ServiceForwardingHeader) (context.Context, net.Conn, publisher.ServiceVisitorAuthentication, func(), error) {
	deny := func() (context.Context, net.Conn, publisher.ServiceVisitorAuthentication, func(), error) {
		return nil, nil, nil, nil, ErrPrivateStream
	}
	if b.prepared.policy == nil || header.Connector == nil {
		return deny()
	}
	entry, initial, err := tunnelv1.ReadConnectorVisitorOpening(stream)
	if err != nil || entry.ServiceID != header.ServiceID || entry.ServiceRunID != header.ServiceRunID || entry.RunNumber != header.RunNumber || entry.VisitorConnectionID != header.VisitorConnectionID || entry.MetadataRevision != uint64(b.prepared.metadataRevision) {
		return deny()
	}
	view, enabled, _ := b.prepared.policy.Current()
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
	if !enabled || keyErr != nil || signatureErr != nil {
		return deny()
	}
	permission, err := visitortoken.VerifyNativeSession(visitortoken.Token(entry.Permission.Token), view, header.Connector.Subject, header.Connector.SessionID, entry.VisitorConnectionID, entry.MetadataRevision, initial, public, signature, time.Now())
	if err != nil {
		return deny()
	}
	source, err := netip.ParseAddr(header.SourceIP)
	if err != nil {
		return deny()
	}
	life, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(life, func() { _ = stream.Close() })
	guard, err := b.prepared.policy.BindNative(permission, source, int64(entry.MetadataRevision), cancel)
	if err != nil {
		cancel()
		stop()
		return deny()
	}
	if err := guard.AllowRenewal(); err != nil {
		guard.Close()
		cancel()
		stop()
		return deny()
	}
	reservation, err := b.prepared.policy.BindReservationFrom(header.Reservation, source, cancel)
	if err != nil {
		guard.Close()
		cancel()
		stop()
		return deny()
	}
	finish := func() { guard.Close(); reservation.Close(); cancel(); stop() }
	reader := tunnel.NewNativeRequestReader(stream, initial, func(proof tunnelv1.NativeVisitorPermission) error {
		view, enabled, _ := b.prepared.policy.Current()
		public, keyErr := base64.RawURLEncoding.Strict().DecodeString(proof.PublicKey)
		signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(proof.Signature)
		if !enabled || keyErr != nil || signatureErr != nil {
			return ErrPrivateStream
		}
		next, err := visitortoken.VerifyNativeRenewalProof(visitortoken.Token(proof.Token), view, header.Connector.Subject, header.Connector.SessionID, entry.VisitorConnectionID, entry.MetadataRevision, nil, public, signature, time.Now())
		if err != nil || next.Subject != permission.Subject {
			return ErrPrivateStream
		}
		return guard.Renew(next)
	})
	visitor := publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
		deadline, err := guard.Deadline()
		return publisher.ServiceVisitorDecision{Allowed: err == nil, ValidUntil: deadline}, err
	}}
	return life, reader, visitor, finish, nil
}
