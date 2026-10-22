package serviceaudit

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateBinding() (ingressv1.ConnectorSessionResult, ingressv1.ServiceStreamResult) {
	bound := ingressv1.ConnectorSessionResult{ServiceId: "svc_0123456789ABCDEFGHIJKL", ConnectorSessionId: "cns_0123456789ABCDEFGHIJKL",
		Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_0123456789ABCDEFGHIJKL", DeviceID: "vdev_0123456789ABCDEFGHIJKL"}), ObservedSourceIp: "192.0.2.9", ExpiresAt: time.Now().Add(time.Minute)}
	admitted := ingressv1.ServiceStreamResult{ServiceId: bound.ServiceId, ConnectorSessionId: bound.ConnectorSessionId,
		Subject: bound.Subject, ObservedSourceIp: bound.ObservedSourceIp, ExpiresAt: bound.ExpiresAt,
		ServiceRunId: "srun_0123456789ABCDEFGHIJKL", RunNumber: 1, GrantRevision: 1, ValidUntil: bound.ExpiresAt, VisitorConnectionId: "vc_0123456789ABCDEFGHIJKL"}
	return bound, admitted
}

func TestPrivateConstructorsSeparateSessionDenialFromAdmittedStream(t *testing.T) {
	bound, admitted := privateBinding()
	denial, err := NewPrivateSessionDenial(bound, admitted.VisitorConnectionId)
	if err != nil || denial.Validate() != nil || denial.RunID != "" || denial.RunNumber != 0 || denial.ServiceID != bound.ServiceId || denial.SourceIP != bound.ObservedSourceIp {
		t.Fatalf("unverified denial scope: %+v %v", denial, err)
	}
	opened, err := NewPrivateStreamObservation(bound, admitted, "connection.open", "allowed", "")
	if err != nil || opened.Validate() != nil || opened.RunID != admitted.ServiceRunId || opened.RunNumber != admitted.RunNumber {
		t.Fatalf("admitted scope: %+v %v", opened, err)
	}
	closed, err := NewPrivateStreamObservation(bound, admitted, "connection.close", "closed", "closed")
	if err != nil || closed.EventID == opened.EventID || closed.VisitorConnectionID != opened.VisitorConnectionID {
		t.Fatal("close did not retain correlation with a new event identity", err)
	}
	for _, change := range []func(*ingressv1.ServiceStreamResult){
		func(a *ingressv1.ServiceStreamResult) { a.ConnectorSessionId = "cns_ABCDEFGHIJKL0123456789" },
		func(a *ingressv1.ServiceStreamResult) {
			a.Subject.IdentityId = new("ident_ABCDEFGHIJKL0123456789")
		},
		func(a *ingressv1.ServiceStreamResult) { a.Subject.DeviceId = new("vdev_ABCDEFGHIJKL0123456789") },
		func(a *ingressv1.ServiceStreamResult) { a.ObservedSourceIp = "192.0.2.10" },
		func(a *ingressv1.ServiceStreamResult) { a.ServiceRunId = "" },
		func(a *ingressv1.ServiceStreamResult) { a.RunNumber = 0 },
		func(a *ingressv1.ServiceStreamResult) { a.GrantRevision = 0 },
	} {
		bad := admitted
		change(&bad)
		if _, err := NewPrivateStreamObservation(bound, bad, "connection.open", "allowed", ""); err != ErrInvalid {
			t.Fatal("accepted mismatched admission", err)
		}
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Outcome = "allowed" },
		func(o *Observation) { o.Outcome = "failed" },
		func(o *Observation) { o.EventType = "connection.close" },
		func(o *Observation) { o.RunNumber = 1 },
		func(o *Observation) { o.ConnectorSessionID = "" },
		func(o *Observation) { o.SourceIP = "" },
	} {
		bad := denial
		change(&bad)
		if bad.Validate() != ErrInvalid {
			t.Fatal("accepted an invalid session-only event")
		}
	}
}
