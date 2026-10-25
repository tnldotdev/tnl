package service

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func (b *Bound) admitDirect(ctx context.Context, stream net.Conn, header tunnelv1.ServiceForwardingHeader, notify func(tunnelv1.ServiceVisitorReference) error) (context.Context, publisher.ServiceVisitorAuthentication, func(), error) {
	deny := func() (context.Context, publisher.ServiceVisitorAuthentication, func(), error) {
		return nil, nil, nil, ErrPrivateStream
	}
	policy := b.prepared.policy
	if policy == nil || notify == nil || !b.prepared.managedPublic || header.Direct == nil || header.Connector != nil {
		return deny()
	}
	view, enabled, _ := policy.Current()
	if !enabled || !view.Public || view.Port != b.prepared.servicePort || view.MetadataRevision != b.prepared.metadataRevision || header.Direct.DestinationPort != view.Port ||
		header.Reservation.IngressID != header.Direct.IngressID || header.Reservation.IngressRunID != header.Direct.IngressRunID || header.Reservation.IngressLeaseRevision != header.Direct.IngressLeaseRevision {
		return deny()
	}
	source, err := netip.ParseAddr(header.SourceIP)
	if err != nil {
		return deny()
	}
	life, cancel := context.WithCancel(ctx)
	closed := make(chan struct{})
	stop := context.AfterFunc(life, func() { _ = stream.Close(); close(closed) })
	reservation, err := policy.BindReservationFrom(header.Reservation, source, cancel)
	if err != nil {
		cancel()
		if !stop() {
			<-closed
		}
		return deny()
	}
	var guard *visitorlease.Guard
	finish := func() {
		if guard != nil {
			guard.Close()
		}
		reservation.Close()
		cancel()
		if !stop() {
			<-closed
		}
	}
	var promotion sync.Once
	var promotionErr error
	promote := func(reference tunnelv1.ServiceVisitorReference) error {
		if !reference.Valid() {
			return ErrPrivateStream
		}
		promotion.Do(func() {
			current, enabled, _ := policy.Current()
			if !enabled || !current.Public || current.MetadataRevision != b.prepared.metadataRevision || life.Err() != nil {
				promotionErr = ErrPrivateStream
				return
			}
			promotionErr = notify(reference)
		})
		return promotionErr
	}
	if b.prepared.managedProtocol == config.ProtocolHTTP {
		return life, b.prepared.managedVisitor(header, promote), finish, nil
	}
	if policy.ClientAuthorities() == nil {
		finish()
		return deny()
	}
	visitor := publisher.CertificateVisitor{Time: func() time.Time {
		view, _, _ := policy.Current()
		return view.AuthorityTime(time.Now())
	}, Check: func(_ context.Context, state tls.ConnectionState) (publisher.ServiceVisitorDecision, error) {
		if guard == nil {
			view, enabled, _ := policy.Current()
			if !enabled || !view.Public || len(state.PeerCertificates) == 0 {
				return publisher.ServiceVisitorDecision{}, ErrPrivateStream
			}
			token, err := visitortoken.CertificateToken(state.PeerCertificates[0])
			if err != nil {
				return publisher.ServiceVisitorDecision{}, err
			}
			permission, err := visitortoken.VerifyCertificate(token, view, state, time.Now())
			if err != nil {
				return publisher.ServiceVisitorDecision{}, err
			}
			guard, err = policy.BindNative(permission, source, b.prepared.metadataRevision, cancel)
			if err != nil {
				return publisher.ServiceVisitorDecision{}, err
			}
			reference, err := visitortoken.ServiceAuditReference(permission.Facts(), state)
			if err != nil {
				return publisher.ServiceVisitorDecision{}, err
			}
			if err := promote(reference); err != nil {
				return publisher.ServiceVisitorDecision{}, err
			}
		}
		deadline, err := guard.Deadline()
		return publisher.ServiceVisitorDecision{Allowed: err == nil, ValidUntil: deadline}, err
	}}
	return life, visitor, finish, nil
}
