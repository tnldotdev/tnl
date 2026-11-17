package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationIngressTerminalRetirementProof(t *testing.T) {
	f := newServicePublicationFixture(t)
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
		f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || state.State != "ready" {
		t.Fatal("terminal proof fixture did not establish a ready service run", state, err)
	}
	ingress, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "terminal-retirement", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	for index, slot := range f.run.Connections {
		if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID,
			f.run.RunID, f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity,
			f.now.Add(time.Duration(index+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	closed, err := f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now.Add(3*time.Second))
	if err != nil || len(closed) != 0 {
		t.Fatalf("a temporary relay outage became terminal proof: %+v %v", closed, err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	closed, err = f.database.ClosedServiceRuns(t.Context(), ingress.IngressLeaseIdentity, []ServiceRunReference{ref}, f.now.Add(4*time.Second))
	if err != nil || !reflect.DeepEqual(closed, []ServiceRunReference{ref}) {
		t.Fatalf("closed run lost its exact terminal tuple: %+v %v", closed, err)
	}
}
