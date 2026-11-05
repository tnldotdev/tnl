package stream

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPairPinsEndpointSecretTrustAndInitialBinding(t *testing.T) {
	encode := func(value byte, size int) string {
		return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, size))
	}
	for _, renewal := range []bool{false, true} {
		for _, boundary := range []string{"valid", "missing session key", "shared secret", "changed trust", "changed session key", "operation", "challenge", "generation"} {
			t.Run(boundary+map[bool]string{false: "/initial", true: "/renewal"}[renewal], func(t *testing.T) {
				now := time.Now()
				signer := Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_" + strings.Repeat("I", 22), DeviceID: "vdev_" + strings.Repeat("D", 22)}}
				pair := controlv1.ConnectorPeerPair{PairId: "cpp_" + strings.Repeat("P", 22), DeliveryId: encode(1, 16), Key: encode(2, 32), SessionKey: encode(3, 32),
					DeliveryGeneration: 17, TrustRevision: 7, BindingState: controlv1.ConnectorPeerPairBindingActive, ServiceId: "service", ServiceRunId: "run", RunNumber: 3,
					PublisherIdentityId: "publisher", Subject: visitorsubject.Wire(signer.Subject), Relays: []controlv1.ConnectorPeerPairRelay{{}, {}}, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
				run := Run{ServiceID: pair.ServiceId, ServiceRunID: pair.ServiceRunId, RunNumber: uint64(pair.RunNumber), TrustRevision: pair.TrustRevision, PairReady: &controlv1.ConnectorPeerPairReady{PublisherIdentityId: pair.PublisherIdentityId}}
				request := controlv1.ConnectorPeerPairRequest{ExpectedRelays: pair.Relays}
				var previous *controlv1.ConnectorPeerPair
				if renewal {
					saved := pair
					previous = &saved
				}
				switch boundary {
				case "missing session key":
					pair.SessionKey = ""
				case "shared secret":
					pair.SessionKey = pair.Key
				case "changed trust":
					pair.TrustRevision++
				case "changed session key":
					pair.SessionKey = encode(4, 32)
				case "operation":
					pair.OperationId = "injected"
				case "challenge":
					pair.BindingChallenge = encode(5, 32)
				case "generation":
					pair.DeliveryGeneration++
				}
				_, _, err := validateConnectorPair(t.Context(), signer, run, request, pair, now, previous)
				valid := boundary == "valid" || !renewal && (boundary == "changed session key" || boundary == "generation")
				if (err == nil) != valid {
					t.Fatal("pair changed the retained secret, trust, or binding", err)
				}
			})
		}
	}
}
