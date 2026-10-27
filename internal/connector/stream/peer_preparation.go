package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// peerOperation is supplied only by the native connection owner. the device
// adapter selects its control bearer; the workload adapter keeps its credential
// in memory. neither credential crosses the stream preparation boundary.
type peerOperation func(context.Context, string, tunnelv1.VisitorSubject, controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error)

type peerPreparation struct {
	signer Signer
	call   peerOperation
}

type preparedPeer struct {
	pair controlv1.NativePeerPair
	// the last selected run and exact assignments bound to this delivery.
	runID  string
	number uint64
	hint   *controlv1.NativePeerPairReady
	until  time.Time
}

// control accepts a signed proof for at most five minutes. leave room for
// clock skew and request transit; an uncertain create cannot safely get a new
// idempotency key while its original admission might still exist.
const peerProofRetryWindow = 4*time.Minute + 50*time.Second

var errPeerProofExpired = fmt.Errorf("%w: signed peer pair request expired; stop and reselect after the prior admission is retired", ErrServiceConnection)

func (preparedPeer) String() string   { return "prepared native peer pair" }
func (preparedPeer) GoString() string { return "prepared native peer pair" }

func clonePairHint(h *controlv1.NativePeerPairReady) *controlv1.NativePeerPairReady {
	if h == nil {
		return nil
	}
	copy := *h
	copy.Relays = slices.Clone(h.Relays)
	return &copy
}

func validPairHint(h *controlv1.NativePeerPairReady) bool {
	// relay lease deadlines are not in this credential-free hint. control
	// rechecks both live leases when it authorizes the signed pair request.
	if h == nil || !opaqueid.Valid(h.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || len(h.Relays) != 2 {
		return false
	}
	a, b := h.Relays[0], h.Relays[1]
	if a.PublisherConnectionId == b.PublisherConnectionId || a.RelayLease.RelayServiceId == b.RelayLease.RelayServiceId || a.RelayLease.RelayId == b.RelayLease.RelayId {
		return false
	}
	for _, relay := range h.Relays {
		if !opaqueid.Valid(relay.PublisherConnectionId, opaqueid.PublisherConnectionPrefix) || relay.AssignmentRevision < 1 ||
			relay.RelayLease.RelayServiceId == "" || relay.RelayLease.RelayId == "" || relay.RelayLease.RelayRunId == "" ||
			relay.RelayLease.RelayLeaseRevision < 1 || relay.RelayAddress == "" || relay.TlsServerName == "" {
			return false
		}
	}
	return true
}

func samePairHint(a, b *controlv1.NativePeerPairReady) bool {
	return validPairHint(a) && validPairHint(b) && a.PublisherIdentityId == b.PublisherIdentityId && slices.Equal(a.Relays, b.Relays)
}

func (p *preparedSelection) refreshPeer(ctx context.Context, run Run) error {
	if p.peerOwner == nil {
		return nil
	}
	owner := p.peerOwner
	if owner.call == nil || owner.signer.Sign == nil || len(owner.signer.PublicKey) != ed25519.PublicKeySize ||
		owner.signer.Subject.Validate() != nil || owner.signer.Subject != run.Subject || !validPairHint(run.PairReady) {
		return ErrServiceConnection
	}
	p.mu.Lock()
	previous, pending := p.peer, p.pendingPeer
	p.mu.Unlock()
	if previous != nil && (previous.runID != run.ServiceRunID || previous.number != run.RunNumber || !samePairHint(previous.hint, run.PairReady)) {
		return ErrServiceConnection
	}
	if previous != nil && !previous.until.After(time.Now()) {
		return ErrSelectionExpired
	}
	if pending != nil && (pending.ServiceRunId != run.ServiceRunID || pending.RunNumber != int64(run.RunNumber) ||
		pending.PublisherIdentityId != run.PairReady.PublisherIdentityId || !slices.Equal(pending.ExpectedRelays, run.PairReady.Relays)) {
		return ErrServiceConnection
	}
	if pending != nil && !pending.RequestedAt.Add(peerProofRetryWindow).After(time.Now()) {
		return errPeerProofExpired
	}
	// a healthy pair is never replaced. renew shortly before its fixed expiry.
	if previous != nil && previous.pair.ExpiresAt.After(time.Now().Add(15*time.Second)) {
		p.mu.Lock()
		p.peer.until = minSelectionTime(run.ValidUntil, minSelectionTime(run.Permission.ExpiresAt, previous.pair.ExpiresAt))
		p.mu.Unlock()
		return nil
	}
	if pending == nil {
		key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			return err
		}
		body := &controlv1.NativePeerPairRequest{ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber),
			PublisherIdentityId: run.PairReady.PublisherIdentityId, Subject: visitorsubject.Wire(owner.signer.Subject),
			Action: "create", IdempotencyKey: key, RequestedAt: time.Now().UTC().Truncate(time.Microsecond),
			ExpectedRelays: slices.Clone(run.PairReady.Relays)}
		if previous != nil {
			body.Action = "renew"
			body.IdempotencyKey = p.createKey
			body.PreviousPairId = &previous.pair.PairId
			body.PreviousGeneration = &previous.pair.DeliveryGeneration
		}
		// the source is excluded from the proof but sent in the request. the
		// adapter overwrites it with the currently authorized source.
		message, err := controlv1.NativePeerPairProofMessage(run.ServiceID, *body)
		if err != nil {
			return ErrServiceConnection
		}
		signature := owner.signer.Sign(message)
		if !ed25519.Verify(owner.signer.PublicKey, message, signature) {
			return ErrServiceConnection
		}
		body.Signature = base64.RawURLEncoding.EncodeToString(signature)
		p.mu.Lock()
		p.pendingPeer = body
		p.mu.Unlock()
		pending = body
	}
	pair, err := owner.call(ctx, run.ServiceID, owner.signer.Subject, *pending)
	if err != nil {
		return err
	}
	if err := validatePeer(pair, run, pending, previous); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil {
		return ErrServiceConnection
	}
	if previous == nil {
		p.createKey = pending.IdempotencyKey
	}
	p.peer = &preparedPeer{pair: pair, runID: run.ServiceRunID, number: run.RunNumber, hint: clonePairHint(run.PairReady),
		until: minSelectionTime(run.ValidUntil, minSelectionTime(run.Permission.ExpiresAt, pair.ExpiresAt))}
	p.pendingPeer = nil
	return nil
}

func validatePeer(pair controlv1.NativePeerPair, run Run, request *controlv1.NativePeerPairRequest, previous *preparedPeer) error {
	if !opaqueid.Valid(pair.PairId, "npp_") || pair.ServiceId != run.ServiceID || pair.ServiceRunId != run.ServiceRunID ||
		pair.RunNumber != int64(run.RunNumber) || pair.PublisherIdentityId != run.PairReady.PublisherIdentityId ||
		!visitorsubject.Same(pair.Subject, request.Subject) || pair.DeliveryGeneration < 1 ||
		!slices.Equal(pair.Relays, request.ExpectedRelays) || !pair.ExpiresAt.After(time.Now()) ||
		pair.ExpiresAt.After(time.Now().Add(5*time.Minute+time.Second)) || pair.ExpiresAt.After(run.ValidUntil) || pair.ExpiresAt.After(run.Permission.ExpiresAt) {
		return ErrServiceConnection
	}
	if _, err := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId); err != nil {
		return ErrServiceConnection
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(pair.Key)
	if err != nil || len(key) != 32 || slices.Equal(key, make([]byte, 32)) || base64.RawURLEncoding.EncodeToString(key) != pair.Key {
		return ErrServiceConnection
	}
	if previous != nil && (pair.PairId != previous.pair.PairId || pair.DeliveryId != previous.pair.DeliveryId ||
		pair.DeliveryGeneration != previous.pair.DeliveryGeneration || pair.Key != previous.pair.Key) {
		return ErrServiceConnection
	}
	return nil
}

// peerCurrent is only used by preparation tests until peer stream admission
// and relay delivery exist. socket arrival must not sign or contact control.
func (p *preparedSelection) peerCurrent() (preparedPeer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.peerFenced || p.peer == nil || !p.until.After(time.Now()) || !p.peer.until.After(time.Now()) ||
		p.peer.runID != p.run.ServiceRunID || p.peer.number != p.run.RunNumber || !samePairHint(p.peer.hint, p.run.PairReady) {
		return preparedPeer{}, ErrServiceConnection
	}
	peer := *p.peer
	peer.pair.Relays = slices.Clone(peer.pair.Relays)
	peer.hint = clonePairHint(peer.hint)
	return peer, nil
}
