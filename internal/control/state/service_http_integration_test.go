package state

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationServiceHTTPSubjectAndAdmissionScope(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {Public: true}}, Services: map[string]ProjectServiceConfiguration{"a": {PublisherGroup: "production", Target: "app:3000"}, "b": {PublisherGroup: "production", Target: "other:3000"}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	start := func(index int, key string) ServiceHTTPRun {
		t.Helper()
		a := replica.assignments.Services[index]
		access := groupAssignmentAccess(t, d, replica, a, now)
		prep, err := d.PrepareServiceRun(t.Context(), a.ServiceID, access.PublisherIdentity, key, now, ServiceMetadata{Protocol: "http", TrustRevision: a.TrustRevision})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), a.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		installPrivateTestCertificate(t, d, prep, run, now)
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
				t.Fatal(err)
			}
			if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
			t.Fatal(err)
		}
		return ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, RunID: run.RunID, Number: run.RunNumber, Token: credentials.ServiceRunToken(run.Token)}
	}
	a, b := start(0, "a"), start(1, "b")
	ports := make([]int32, 0, len(applied.Services))
	for _, service := range applied.Services {
		ports = append(ports, int32(service.Port))
	}
	slices.Sort(ports)
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "service-http", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), IngressPoolID: PrimaryIngressPoolID, ServicePorts: ports, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(auth ServiceHTTPRun) controlv1.ServiceHTTPVisitorRequest {
		t.Helper()
		port := 0
		for _, s := range applied.Services {
			if s.ServiceID == auth.Subject.ID {
				port = s.Port
			}
		}
		visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		if _, err := d.AdmitDirectServiceVisitor(t.Context(), lease.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, port, netip.MustParseAddr("192.0.2.10"), now); err != nil {
			t.Fatal(err)
		}
		return controlv1.ServiceHTTPVisitorRequest{RunNumber: auth.Number, VisitorConnectionId: visitor, SourceIp: "192.0.2.10", DestinationPort: port, Credential: controlv1.ServiceHTTPCredential{Kind: "none"}}
	}
	input := admit(a)
	grant, err := d.CreateServiceHTTPGrant(t.Context(), a.Subject.ID, r.ActorID, controlv1.CreateServiceHTTPGrantRequest{Kind: "token", ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	input.Credential = controlv1.ServiceHTTPCredential{Kind: "token", Secret: &grant.Secret}
	decision, err := d.AuthorizeServiceHTTPVisitor(t.Context(), a, input, now)
	if err != nil || !decision.Allowed || decision.Admitted {
		t.Fatal("HTTP credential bypassed ingress promotion", decision, err)
	}
	if err = d.PromoteDirectServiceVisitor(t.Context(), lease.IngressLeaseIdentity, input.VisitorConnectionId, now); err != nil {
		t.Fatal(err)
	}
	decision, err = d.AuthorizeServiceHTTPVisitor(t.Context(), a, input, now)
	if err != nil || !decision.Allowed || !decision.Admitted {
		t.Fatal(decision, err)
	}
	deny := func(auth ServiceHTTPRun, request controlv1.ServiceHTTPVisitorRequest) {
		t.Helper()
		decision, err := d.AuthorizeServiceHTTPVisitor(t.Context(), auth, request, now)
		if err == nil && decision.Allowed {
			t.Fatal("widened service HTTP credential")
		}
	}
	wrong := input
	wrong.SourceIp = "192.0.2.11"
	deny(a, wrong)
	wrong = input
	wrong.DestinationPort++
	deny(a, wrong)
	wrong = input
	wrong.RunNumber++
	deny(a, wrong)
	wrongAuth := a
	wrongAuth.Subject.Kind = visitorscope.PublicURL
	deny(wrongAuth, input)
	wrong = admit(b)
	wrong.Credential = input.Credential
	deny(b, wrong)
	wrong = input
	wrong.Credential.Kind = "share"
	deny(a, wrong)
	wrong = input
	wrong.Credential.Secret = new("shr_0123456789abcdefghijkl." + strings.Repeat("A", 43))
	deny(a, wrong)
	wrong = input
	wrong.Credential.Certificate = new([]byte{1})
	deny(a, wrong)
	// browser credentials capture ready runs and stay separate from legacy URL
	// sessions and managed bearer grants. a new pool member cannot redeem them.
	binding := bytes.Repeat([]byte{7}, 32)
	state, err := d.BeginServiceBrowserLogin(t.Context(), a.Subject, "/settings?tab=1", strings.Repeat("n", 43), strings.Repeat("v", 43), binding, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ConsumeBrowserLogin(t.Context(), state, bytes.Repeat([]byte{8}, 32), now); !errors.Is(err, ErrPreviewAccess) {
		t.Fatal("login binding ignored", err)
	}
	attempt, err := d.ConsumeBrowserLogin(t.Context(), state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	issued := browserTestControlSession(t, d, r.ActorID, now)
	handoff, err := d.IssueBrowserHandoff(t.Context(), attempt, BrowserAccessSession{IdentityID: r.ActorID, DisplayName: "operator", AccessToken: issued.AccessToken.String(), RefreshToken: issued.RefreshToken.String(), AccessExpiresAt: issued.AccessExpiresAt, ExpiresAt: issued.RefreshExpiresAt}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(handoff.Origin, ":"+strconv.Itoa(input.DestinationPort)) {
		t.Fatal("handoff dropped allocated port", handoff.Origin)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), b, handoff.Token, now); err == nil {
		t.Fatal("other service redeemed handoff")
	}
	replica = enrollAppliedGroup(t, d, r, enrollment, now)
	later := start(0, "later")
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), later, handoff.Token, now); err == nil {
		t.Fatal("later run redeemed handoff")
	}
	redemption, err := d.RedeemServiceBrowserHandoff(t.Context(), a, handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), a, handoff.Token, now); err == nil {
		t.Fatal("handoff replay")
	}
	input.Credential = controlv1.ServiceHTTPCredential{Kind: "browser", Secret: &redemption.CookieSecret}
	decision, err = d.AuthorizeServiceHTTPVisitor(t.Context(), a, input, now)
	if err != nil || !decision.Allowed {
		t.Fatal("current browser was denied", decision, err)
	}
	if _, err = d.BrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now); err == nil {
		t.Fatal("managed browser widened legacy URL scope")
	}
	if _, err = d.ServiceBrowserSession(t.Context(), later, redemption.CookieSecret, false, now); err == nil {
		t.Fatal("browser session widened run scope")
	}
	// manual/company suspension invalidates both a signed-in visitor and the
	// current authority behind a service-scoped bearer grant.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, r.TeamID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	deny(a, input)
	input.Credential = controlv1.ServiceHTTPCredential{Kind: "token", Secret: &grant.Secret}
	deny(a, input)
	status, err := d.DirectServiceVisitorStatus(t.Context(), lease.IngressLeaseIdentity, input.VisitorConnectionId, now)
	if err != nil || status.State != DirectVisitorDenied {
		t.Fatal("ingress retained suspended HTTP authority", status, err)
	}
}

func mustOpaqueID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
