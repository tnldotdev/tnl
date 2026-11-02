package relay

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorRunCannotExhaustRelayCapacity(t *testing.T) {
	a := &ConnectorAcceptor{
		CurrentLease: func() relayv1.RelayLease { return relayv1.RelayLease{} },
		SigningKey:   ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		Claim:        &HTTPControlClient{}, Publishers: &ServiceRegistry{},
	}
	var releases []func()
	for i := range maxConnectorSessionsPerRun {
		proof := tunnelv1.ConnectorPairLegProof{ServiceRunID: "run-a", PairID: string(rune('a' + i)), DeliveryGeneration: 1}
		release, err := a.reserve(proof)
		if err != nil {
			t.Fatal("run was limited before its share", err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	_, err := a.reserve(tunnelv1.ConnectorPairLegProof{ServiceRunID: "run-a", PairID: "extra", DeliveryGeneration: 1})
	var rejected *tunnel.ProtocolError
	if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
		t.Fatal("one run exceeded its relay share", err)
	}
	other, err := a.reserve(tunnelv1.ConnectorPairLegProof{ServiceRunID: "run-b", PairID: "other", DeliveryGeneration: 1})
	if err != nil {
		t.Fatal("one run blocked another run", err)
	}
	other()
	releases[0]()
	if reopened, err := a.reserve(tunnelv1.ConnectorPairLegProof{ServiceRunID: "run-a", PairID: "new", DeliveryGeneration: 1}); err != nil {
		t.Fatal("released run share not reusable", err)
	} else {
		reopened()
	}
}
