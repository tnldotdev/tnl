package connectorfixture

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRetirementFencesPairWithoutResettingJoinedControl(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	const owner = "fixture-owner"
	pair := controlv1.ConnectorPeerPair{
		ServiceId: "svc_" + strings.Repeat("s", 22), ServiceRunId: "srun_" + strings.Repeat("r", 22),
		PublisherIdentityId: "pub_" + strings.Repeat("p", 22), PairId: "cpp_" + strings.Repeat("c", 22),
		DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", RunNumber: 1,
		ObservedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	key := [32]byte{1}
	visitor := NewJoinedVisitor(t.Context(), tunnelv1.ConnectorPeerVisitorEntry{}, pair.ExpiresAt, func() error { return nil })
	control := NewJoinedControl(t.Context(), tunnelv1.ConnectorControlScope{}, nil)
	defer control.Retire()
	p := &connectorPair{
		seen: map[string]*JoinedVisitor{"existing": visitor}, control: control,
		retirement: NewRetirement(pair, owner, public, key),
	}
	n := &Connector{service: pair.ServiceId, pairs: map[string]*connectorPair{owner: p}}
	body := controlv1.ConnectorPeerPairRetireRequest{
		ServiceRunId: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityId: pair.PublisherIdentityId,
		DeliveryId: pair.DeliveryId, IdempotencyKey: owner, RequestedAt: now,
	}
	proof, err := controlv1.ConnectorPeerPairRetireProof(pair.ServiceId, pair.PairId, body)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := proof.SessionProof(key[:])
	if err != nil {
		t.Fatal(err)
	}
	message, err := proof.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	body.SessionProof = base64.RawURLEncoding.EncodeToString(mac)
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	invalid := body
	invalid.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := n.Retire(t.Context(), pair.PairId, invalid); err == nil || p.retired || visitor.Context.Err() != nil || control.Context.Err() != nil {
		t.Fatal("unverified retirement changed fixture authority")
	}
	for range 2 {
		receipt, err := n.Retire(t.Context(), pair.PairId, body)
		if err != nil || receipt.ValidateFor(pair.ServiceId, pair.PairId, body) != nil || !p.retired {
			t.Fatal("signed retirement did not fence its exact pair", err)
		}
		if visitor.Context.Err() != context.Canceled {
			t.Fatal("retirement retained application authority")
		}
		if control.Context.Err() != nil {
			t.Fatal("retirement reset control before the connector could join cleanup")
		}
	}
}
