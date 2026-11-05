package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func rebindFixture(t *testing.T) (Signer, Run, controlv1.ConnectorPeerPair, controlv1.ConnectorPeerPairRebindRequest, controlv1.ConnectorPeerPairRebindState) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: connectorID(t, opaqueid.IdentityPrefix), DeviceID: connectorID(t, "vdev_")}, PublicKey: public, Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}
	run := Run{ServiceID: connectorID(t, opaqueid.ServicePrefix), ServiceRunID: connectorID(t, opaqueid.ServiceRunPrefix), RunNumber: 3, TrustRevision: 7, Protocol: "tcp", ValidUntil: time.Now().Add(time.Minute)}
	relays := []controlv1.ConnectorPeerPairRelay{}
	for _, name := range []string{"a", "b"} {
		relays = append(relays, controlv1.ConnectorPeerPairRelay{PublisherConnectionId: connectorID(t, opaqueid.PublisherConnectionPrefix), AssignmentRevision: 4,
			RelayAddress: name + ".example:443", TlsServerName: name + ".example", RelayLease: controlv1.ConnectorPeerRelayLease{RelayServiceId: name, RelayId: name + "-process", RelayRunId: connectorID(t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 2}})
	}
	encode := func(size int, value byte) string {
		data := make([]byte, size)
		for i := range data {
			data[i] = value
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	original := controlv1.ConnectorPeerPair{PairId: connectorID(t, "cpp_"), DeliveryId: encode(16, 1), Key: encode(32, 2), SessionKey: encode(32, 3),
		DeliveryGeneration: 1, BindingState: "suspended", ServiceId: run.ServiceID, ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber), TrustRevision: run.TrustRevision,
		PublisherIdentityId: connectorID(t, opaqueid.PublisherIdentityPrefix), Subject: visitorsubject.Wire(signer.Subject), Relays: relays, ObservedAt: now, ExpiresAt: now.Add(time.Minute), SourceIp: new("192.0.2.1")}
	pending := original
	pending.DeliveryGeneration, pending.Key, pending.BindingState, pending.SourceIp = 2, encode(32, 4), "prepared", nil
	pending.ExpiresAt = now.Add(9 * time.Second)
	pending.OperationId, pending.BindingChallenge = connectorID(t, opaqueid.IdempotencyPrefix), encode(32, 5)
	body, err := connectorRebindRequest(signer, run, original, connectorID(t, opaqueid.IdempotencyPrefix), "prepare", pending.OperationId, 1, relays, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	state := controlv1.ConnectorPeerPairRebindState{Active: &original, Pending: &pending, HighWaterGeneration: 2, ReadyRelays: relays,
		PendingUntil: new(now.Add(9 * time.Second)), Operation: &controlv1.ConnectorPeerPairRebindOperation{OperationId: pending.OperationId, DeliveryGeneration: 2, Status: "pending"}}
	return signer, run, original, body, state
}

func TestConnectorRebindSnapshotPinsOwnerRunTrustAndHighWater(t *testing.T) {
	for _, boundary := range []string{"valid", "owner", "delivery", "run", "number", "publisher", "subject", "trust", "session key", "shared key", "noncanonical challenge", "reused key", "revision rollback", "ready shape", "wrong operation", "mixed observation", "unbounded pending", "source", "legacy state", "missing operation"} {
		t.Run(boundary, func(t *testing.T) {
			signer, run, original, request, state := rebindFixture(t)
			switch boundary {
			case "owner":
				state.Pending.PairId = connectorID(t, "cpp_")
			case "delivery":
				state.Pending.DeliveryId = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
			case "run":
				state.Pending.ServiceRunId = connectorID(t, opaqueid.ServiceRunPrefix)
			case "number":
				state.Pending.RunNumber++
			case "publisher":
				state.Pending.PublisherIdentityId = connectorID(t, opaqueid.PublisherIdentityPrefix)
			case "subject":
				state.Pending.Subject.DeviceId = new(connectorID(t, "vdev_"))
			case "trust":
				state.Pending.TrustRevision++
			case "session key":
				state.Pending.SessionKey = state.Pending.Key
			case "shared key":
				state.Pending.Key = original.SessionKey
			case "noncanonical challenge":
				state.Pending.BindingChallenge += "\n"
			case "reused key":
				state.Pending.Key = original.Key
			case "revision rollback":
				state.HighWaterGeneration = 1
			case "ready shape":
				state.ReadyRelays = state.ReadyRelays[:1]
			case "wrong operation":
				state.Operation.OperationId = connectorID(t, opaqueid.IdempotencyPrefix)
			case "mixed observation":
				state.Pending.ObservedAt = state.Pending.ObservedAt.Add(time.Millisecond)
			case "unbounded pending":
				state.PendingUntil = new(state.Pending.ObservedAt.Add(11 * time.Second))
			case "source":
				state.Pending.SourceIp = new("::ffff:192.0.2.1")
			case "legacy state":
				state.Active.BindingState = ""
			case "missing operation":
				state.Operation = nil
			}
			started := time.Now().Add(-time.Second)
			until, err := validateConnectorRebindState(t.Context(), signer, run, original, request, state, started, 1)
			if boundary == "valid" {
				if err != nil || !until.Equal(started.Add(9*time.Second)) {
					t.Fatal("valid snapshot did not subtract request transit", err)
				}
			} else if err == nil {
				t.Fatal("invalid snapshot could replace the retained binding")
			}
		})
	}
}

func TestConnectorRebindLostRepliesRepeatExactSignedPhase(t *testing.T) {
	for _, phase := range []controlv1.ConnectorPeerPairRebindPhase{"inspect", "prepare", "abort"} {
		t.Run(string(phase), func(t *testing.T) {
			signer, run, original, prepare, state := rebindFixture(t)
			operation, relays := prepare.OperationId, original.Relays
			if phase == "inspect" {
				operation = ""
			}
			if phase != "prepare" {
				relays = nil
			}
			request, err := connectorRebindRequest(signer, run, original, prepare.IdempotencyKey, phase, operation, 2, relays, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			message, err := controlv1.ConnectorPeerPairRebindProofMessage(run.ServiceID, original.PairId, request)
			signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(request.Signature)
			if err != nil || decodeErr != nil || !ed25519.Verify(signer.PublicKey, message, signature) {
				t.Fatal("phase proof was not signed by the retained owner")
			}
			first := request
			calls := 0
			result, err := requestConnectorPair(t.Context(), func() (controlv1.ConnectorPeerPairRebindState, error) {
				calls++
				if !reflect.DeepEqual(request, first) {
					t.Error("uncertain reply changed the signed phase, timestamp, or operation")
				}
				if calls < 3 {
					return controlv1.ConnectorPeerPairRebindState{}, &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
				}
				return state, nil
			})
			if err != nil || calls != 3 || result.HighWaterGeneration != state.HighWaterGeneration {
				t.Fatal("lost replies did not retain the phase request", err)
			}
		})
	}
}

func TestConnectorRebindExpiredAndAbortedRevisionCannotReinstallPredecessor(t *testing.T) {
	signer, run, original, prepare, state := rebindFixture(t)
	if _, err := validateConnectorRebindState(t.Context(), signer, run, original, prepare, state, time.Now().Add(-10*time.Second), 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired pending binding received a fresh local deadline", err)
	}
	state.Pending, state.PendingUntil, state.Operation.Status = nil, nil, "aborted"
	if _, err := validateConnectorRebindState(t.Context(), signer, run, original, prepare, state, time.Now(), 2); err != nil {
		t.Fatal("abort lost the operation's high-water revision", err)
	}
	state.HighWaterGeneration, state.Operation = 1, nil
	if _, err := validateConnectorRebindState(t.Context(), signer, run, original, prepare, state, time.Now(), 2); err == nil {
		t.Fatal("an old observation rolled back the aborted revision")
	}
}
