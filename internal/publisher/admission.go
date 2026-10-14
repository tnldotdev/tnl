package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionPromotion struct {
	mu      sync.Mutex
	request func(context.Context) error
	called  bool
	err     error
}

func (p *admissionPromotion) allow(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.called {
		return p.err
	}
	p.called = true
	if p.request == nil {
		p.err = errors.New("publisher: no ingress admission path")
		return p.err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p.err = p.request(ctx)
	return p.err
}

func promoteVisitorConnection(ctx context.Context, session *tunnel.Session, ref tunnelv1.PublisherConnectionRef, visitorID string) error {
	stream, err := session.OpenPublisherAdmissionStream(ctx, tunnelv1.AdmissionHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream,
		VisitorConnectionID: visitorID, PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID,
		PublishRunNumber: ref.PublishRunNumber, PublisherConnectionID: ref.PublisherConnectionID,
		ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, RelayServiceID: ref.RelayServiceID,
	})
	if err != nil {
		return fmt.Errorf("publisher: open visitor admission: %w", err)
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	result, err := tunnelv1.ReadAdmissionResult(stream)
	if err != nil {
		return fmt.Errorf("publisher: read ingress admission acknowledgement: %w", err)
	}
	if result.Type != tunnelv1.StreamAccepted {
		return &tunnel.ProtocolError{Code: result.Code}
	}
	return nil
}
