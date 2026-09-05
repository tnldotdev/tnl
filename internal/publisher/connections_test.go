package publisher

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestSamePublisherConnectionPlanIgnoresLifecycleState(t *testing.T) {
	assigned := controlv1.PublisherConnectionPlan{
		ConnectionAssignmentRevision:           1,
		ConnectionSlot:                         1,
		PublisherConnectionCredential:          "credential",
		PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
		PublisherConnectionId:                  "connection_1",
		RelayAddress:                           "relay.example:443",
		RelayServiceId:                         "relay_service_1",
		State:                                  controlv1.PublisherConnectionStateAssigned,
		TlsServerName:                          "relay.example",
	}
	ready := assigned
	ready.State = controlv1.PublisherConnectionStateReady
	if !samePublisherConnectionPlan(assigned, ready) {
		t.Fatal("a lifecycle-state update replaced the same publisher connection assignment")
	}
	replaced := ready
	replaced.ConnectionAssignmentRevision++
	if samePublisherConnectionPlan(assigned, replaced) {
		t.Fatal("a new assignment revision reused the existing publisher connection")
	}
}
