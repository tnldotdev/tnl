package serviceaudit

import (
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateBinding() (ingressv1.ConnectorSessionResult, tunnelv1.ConnectorVisitorEntry, tunnelv1.StreamReservation, visitortoken.Permission) {
	bound := ingressv1.ConnectorSessionResult{ServiceId: "svc_0123456789ABCDEFGHIJKL", ConnectorSessionId: "cns_0123456789ABCDEFGHIJKL",
		Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_0123456789ABCDEFGHIJKL", DeviceID: "vdev_0123456789ABCDEFGHIJKL"}), ObservedSourceIp: "192.0.2.9", ExpiresAt: time.Now().Add(time.Minute)}
	entry := tunnelv1.ConnectorVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorVisitorStream, ServiceID: bound.ServiceId, ServiceRunID: "srun_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", MetadataRevision: 1,
		Permission: tunnelv1.NativeVisitorPermission{Token: "signed-permission", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
	reservation := tunnelv1.StreamReservation{ID: "sres_0123456789ABCDEFGHIJKL", AllocationID: "salloc_0123456789ABCDEFGHIJKL", Sequence: 1, ResourceKind: "service", ResourceID: entry.ServiceID, RunID: entry.ServiceRunID, RunNumber: 1, VisitorConnectionID: entry.VisitorConnectionID, IngressID: "ingress", IngressRunID: "process", IngressLeaseRevision: 1}
	permission := visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: entry.ServiceID}, Subject: visitortoken.Device{IdentityID: "ident_0123456789ABCDEFGHIJKL", DeviceID: "vdev_0123456789ABCDEFGHIJKL"}}
	return bound, entry, reservation, permission
}

func TestPrivateConstructorsSeparateSessionDenialFromAdmittedStream(t *testing.T) {
	bound, entry, reservation, permission := privateBinding()
	denial, err := NewPrivateSessionDenial(bound, entry.VisitorConnectionID)
	if err != nil || denial.Validate() != nil || denial.RunID != "" || denial.RunNumber != 0 || denial.ServiceID != bound.ServiceId || denial.SourceIP != bound.ObservedSourceIp {
		t.Fatalf("unverified denial scope: %+v %v", denial, err)
	}
	opened, err := NewNativeStreamObservation(bound, entry, reservation, permission, "connection.open", "allowed", "")
	if err != nil || opened.Validate() != nil || opened.RunID != entry.ServiceRunID || opened.RunNumber != int64(entry.RunNumber) || opened.StreamAllocationID != reservation.AllocationID || opened.SourceIP != bound.ObservedSourceIp || opened.ConnectorSessionID != bound.ConnectorSessionId {
		t.Fatalf("admitted scope: %+v %v", opened, err)
	}
	closed, err := NewNativeStreamObservation(bound, entry, reservation, permission, "connection.close", "closed", "closed")
	if err != nil || closed.EventID == opened.EventID || closed.VisitorConnectionID != opened.VisitorConnectionID {
		t.Fatal("close did not retain correlation with a new event identity", err)
	}
	for _, change := range []func(*tunnelv1.ConnectorVisitorEntry){
		func(a *tunnelv1.ConnectorVisitorEntry) { a.ServiceRunID = "" },
		func(a *tunnelv1.ConnectorVisitorEntry) { a.RunNumber = 0 },
		func(a *tunnelv1.ConnectorVisitorEntry) { a.MetadataRevision = 0 },
		func(a *tunnelv1.ConnectorVisitorEntry) { a.VisitorConnectionID = "vc_ABCDEFGHIJKL0123456789" },
	} {
		bad := entry
		change(&bad)
		if _, err := NewNativeStreamObservation(bound, bad, reservation, permission, "connection.open", "allowed", ""); err != ErrInvalid {
			t.Fatal("accepted mismatched admission", err)
		}
	}
	for _, change := range []func(*ingressv1.ConnectorSessionResult){
		func(b *ingressv1.ConnectorSessionResult) { b.ConnectorSessionId = "not-an-authenticated-session" },
		func(b *ingressv1.ConnectorSessionResult) { b.Subject.IdentityId = new("ident_ABCDEFGHIJKL0123456789") },
		func(b *ingressv1.ConnectorSessionResult) { b.Subject.DeviceId = new("vdev_ABCDEFGHIJKL0123456789") },
	} {
		bad := bound
		change(&bad)
		if _, err := NewNativeStreamObservation(bad, entry, reservation, permission, "connection.open", "allowed", ""); err != ErrInvalid {
			t.Fatal("permission changed its authenticated subject", err)
		}
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Outcome = "allowed" }, func(o *Observation) { o.Outcome = "failed" },
		func(o *Observation) { o.EventType = "connection.close" }, func(o *Observation) { o.RunNumber = 1 },
		func(o *Observation) { o.ConnectorSessionID = "" }, func(o *Observation) { o.SourceIP = "" },
	} {
		bad := denial
		change(&bad)
		if bad.Validate() != ErrInvalid {
			t.Fatal("accepted an invalid session-only event")
		}
	}
}
