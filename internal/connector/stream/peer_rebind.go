package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func connectorRebindRequest(signer Signer, run Run, pair controlv1.ConnectorPeerPair, owner string, phase controlv1.ConnectorPeerPairRebindPhase, operation string, generation int64, relays []controlv1.ConnectorPeerPairRelay, challenge string, proofs []controlv1.ConnectorPeerPairPathProof) (controlv1.ConnectorPeerPairRebindRequest, error) {
	body := controlv1.ConnectorPeerPairRebindRequest{Phase: phase, IdempotencyKey: owner, OperationId: operation, ExpectedGeneration: generation,
		RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber), PublisherIdentityId: pair.PublisherIdentityId,
		TrustRevision: run.TrustRevision, Subject: visitorsubject.Wire(signer.Subject), ExpectedRelays: append([]controlv1.ConnectorPeerPairRelay{}, relays...),
		BindingChallenge: challenge, PathProofs: append([]controlv1.ConnectorPeerPairPathProof{}, proofs...)}
	message, err := controlv1.ConnectorPeerPairRebindProofMessage(run.ServiceID, pair.PairId, body)
	if err != nil {
		return body, err
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return body, ErrServiceConnection
	}
	body.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return body, nil
}

// inspect supplies hints for the original owner, never a second run selection.
// deadlines from observations may narrow a local fence, but cannot renew it.
func validateConnectorRebindState(ctx context.Context, signer Signer, run Run, original controlv1.ConnectorPeerPair, request controlv1.ConnectorPeerPairRebindRequest, state controlv1.ConnectorPeerPairRebindState, started time.Time, highWater int64) (time.Time, error) {
	if ctx.Err() != nil || state.Active == nil || state.HighWaterGeneration < highWater || state.HighWaterGeneration < original.DeliveryGeneration ||
		len(state.ReadyRelays) != 0 && len(state.ReadyRelays) != 2 {
		return time.Time{}, ErrServiceConnection
	}
	if _, err := connectorPairSecret(original.SessionKey); err != nil {
		return time.Time{}, err
	}
	if len(state.ReadyRelays) == 2 {
		shape := request
		shape.Phase, shape.OperationId, shape.ExpectedGeneration = "prepare", opaqueid.IdempotencyPrefix+"0000000000000000000000", state.HighWaterGeneration
		shape.ExpectedRelays, shape.BindingChallenge, shape.PathProofs = state.ReadyRelays, "", nil
		if _, err := controlv1.ConnectorPeerPairRebindProofMessage(run.ServiceID, original.PairId, shape); err != nil {
			return time.Time{}, ErrServiceConnection
		}
	}
	validate := func(pair *controlv1.ConnectorPeerPair, pending bool) bool {
		if pair == nil {
			return true
		}
		if pair.PairId != original.PairId || pair.DeliveryId != original.DeliveryId || pair.ServiceId != run.ServiceID || pair.ServiceRunId != run.ServiceRunID ||
			pair.RunNumber != int64(run.RunNumber) || pair.PublisherIdentityId != original.PublisherIdentityId || pair.TrustRevision != run.TrustRevision ||
			pair.SessionKey != original.SessionKey || !visitorsubject.Equal(pair.Subject, signer.Subject) || len(pair.Relays) != 2 ||
			pair.DeliveryGeneration < original.DeliveryGeneration || pair.DeliveryGeneration > state.HighWaterGeneration || pair.ObservedAt.IsZero() ||
			!pair.ExpiresAt.After(pair.ObservedAt) || pair.ExpiresAt.Sub(pair.ObservedAt) > 5*time.Minute {
			return false
		}
		if _, err := connectorPairSecret(pair.Key); err != nil || pair.Key == pair.SessionKey {
			return false
		}
		if pair.SourceIp != nil {
			address, err := netip.ParseAddr(*pair.SourceIp)
			if err != nil || address.String() != *pair.SourceIp || address.IsUnspecified() || address.Is4In6() || address.Zone() != "" {
				return false
			}
		}
		if pair.PublisherPreparedUntil != nil && pair.PublisherPreparedUntil.After(pair.ExpiresAt) || pair.PublisherProvedUntil != nil && pair.PublisherProvedUntil.After(pair.ExpiresAt) {
			return false
		}
		if pair.DeliveryGeneration == original.DeliveryGeneration {
			if pending || pair.Key != original.Key || pair.OperationId != original.OperationId || pair.BindingChallenge != original.BindingChallenge ||
				pair.Relays[0] != original.Relays[0] || pair.Relays[1] != original.Relays[1] || original.SourceIp != nil && (pair.SourceIp == nil || *pair.SourceIp != *original.SourceIp) {
				return false
			}
		} else {
			challenge, err := base64.RawURLEncoding.Strict().DecodeString(pair.BindingChallenge)
			if !opaqueid.Valid(pair.OperationId, opaqueid.IdempotencyPrefix) || err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != pair.BindingChallenge || pair.Key == original.Key {
				return false
			}
		}
		if pending {
			return pair.BindingState == "prepared" || pair.BindingState == "installed" || pair.BindingState == "proved"
		}
		return pair.BindingState == "active" || pair.BindingState == "suspended"
	}
	if !validate(state.Active, false) || !validate(state.Pending, true) {
		return time.Time{}, ErrServiceConnection
	}
	if state.Active != nil && state.Pending != nil && (state.Active.DeliveryGeneration >= state.Pending.DeliveryGeneration || !state.Active.ObservedAt.Equal(state.Pending.ObservedAt)) {
		return time.Time{}, ErrServiceConnection
	}
	if state.Operation != nil {
		op := state.Operation
		if !opaqueid.Valid(op.OperationId, opaqueid.IdempotencyPrefix) || op.DeliveryGeneration != state.HighWaterGeneration || op.DeliveryGeneration < original.DeliveryGeneration ||
			op.Status != "pending" && op.Status != "active" && op.Status != "aborted" && op.Status != "expired" {
			return time.Time{}, ErrServiceConnection
		}
		if request.OperationId != "" && op.OperationId != request.OperationId ||
			op.Status == "pending" && (state.Pending == nil || state.Pending.OperationId != op.OperationId || state.Pending.DeliveryGeneration != op.DeliveryGeneration) ||
			op.Status == "active" && (state.Active == nil || state.Active.OperationId != op.OperationId || state.Active.DeliveryGeneration != op.DeliveryGeneration) ||
			(op.Status == "aborted" || op.Status == "expired") && state.Pending != nil {
			return time.Time{}, ErrServiceConnection
		}
	} else if state.Pending != nil || state.HighWaterGeneration != original.DeliveryGeneration || request.OperationId != "" {
		return time.Time{}, ErrServiceConnection
	}
	if state.Pending == nil {
		if state.PendingUntil != nil {
			return time.Time{}, ErrServiceConnection
		}
		return time.Time{}, nil
	}
	if state.Operation == nil || state.Operation.Status != "pending" || state.PendingUntil == nil ||
		!state.PendingUntil.After(state.Pending.ObservedAt) || state.PendingUntil.Sub(state.Pending.ObservedAt) > 10*time.Second || state.Pending.ExpiresAt.After(*state.PendingUntil) {
		return time.Time{}, ErrServiceConnection
	}
	until := started.Add(state.PendingUntil.Sub(state.Pending.ObservedAt))
	if !until.After(time.Now()) {
		return time.Time{}, context.DeadlineExceeded
	}
	return until, nil
}
