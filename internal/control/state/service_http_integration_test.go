package state

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
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
	portFor := func(auth ServiceHTTPRun) int {
		t.Helper()
		for _, service := range applied.Services {
			if service.ServiceID == auth.Subject.ID {
				return service.Port
			}
		}
		t.Fatal("service lost its saved endpoint port")
		return 0
	}
	for _, service := range applied.Services {
		ports = append(ports, int32(service.Port))
	}
	slices.Sort(ports)
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "service-http", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), IngressPoolID: PrimaryIngressPoolID, ServicePorts: ports, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	prepareVisitorTokenKeys(t, d, now)
	read := func(scope visitorscope.Scope) visitortoken.View {
		t.Helper()
		wire, err := d.ReadIngressVisitorPolicy(t.Context(), lease.IngressLeaseIdentity, scope, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(wire)
		if err != nil || !update.Enabled || !update.View.Public {
			t.Fatal("service HTTP policy lost its direct scope", err)
		}
		return update.View
	}
	parent := browserTestControlSession(t, d, r.ActorID, now)
	principal := WithControlPrincipal(t.Context(), ControlPrincipal{SessionID: parent.SessionID, IdentityID: r.ActorID})
	grant, err := d.CreateVisitorGrantCredentials(principal, testVisitorIssuer, a.Subject, "token", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	view := read(a.Subject)
	if view.Port != uint16(portFor(a)) {
		t.Fatal("permission changed the direct destination port")
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, view, now); err != nil {
		t.Fatal("signed HTTP credential was not locally verifiable", err)
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, read(b.Subject), now); err == nil {
		t.Fatal("credential widened to another service")
	}
	wrongScope := view
	wrongScope.Scope = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: a.Subject.ID}
	if _, err := visitortoken.VerifyBearer(grant.Token, wrongScope, now); err == nil {
		t.Fatal("service credential became a public URL grant")
	}
	wrongPort := view
	wrongPort.Port++
	if _, err := visitortoken.VerifyBearer(grant.Token, wrongPort, now); err == nil {
		t.Fatal("credential crossed the approved direct port")
	}
	if _, err := visitortoken.VerifyBearer(visitortoken.Token("shr_0123456789abcdefghijkl."+strings.Repeat("A", 43)), view, now); err == nil {
		t.Fatal("public URL share became a service credential")
	}
	// browser handoffs capture the ready run IDs. neither another service, a
	// later run, nor the public URL browser API may redeem the same sign-in.
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
	if !strings.HasSuffix(handoff.Origin, ":"+strconv.Itoa(portFor(a))) {
		t.Fatal("handoff dropped allocated port", handoff.Origin)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), b, testVisitorIssuer, handoff.Token, now); err == nil {
		t.Fatal("other service redeemed handoff")
	}
	replica = enrollAppliedGroup(t, d, r, enrollment, now)
	later := start(0, "later")
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), later, testVisitorIssuer, handoff.Token, now); err == nil {
		t.Fatal("later run redeemed handoff")
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), a, "", handoff.Token, now); err == nil {
		t.Fatal("invalid visitor signing issuer prepared a browser handoff")
	}
	redemption, err := d.RedeemServiceBrowserHandoff(t.Context(), a, testVisitorIssuer, handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemServiceBrowserHandoff(t.Context(), a, testVisitorIssuer, handoff.Token, now); err == nil {
		t.Fatal("handoff replay")
	}
	browserPermission, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, a.Subject, BrowserSessionTokenSource{Secret: redemption.CookieSecret}, now)
	if err != nil {
		t.Fatal("redeemed browser did not receive a scoped token", err)
	}
	if _, err := visitortoken.VerifyBearer(browserPermission.Token, read(a.Subject), now); err != nil {
		t.Fatal("signed-in visitor was denied locally", err)
	}
	if _, err := visitortoken.VerifyBearer(redemption.Issued.Token, read(a.Subject), now); err != nil {
		t.Fatal("atomic handoff returned an unverified visitor permission", err)
	}
	if _, err = d.BrowserSession(t.Context(), a.Subject.ID, redemption.CookieSecret, now); err == nil {
		t.Fatal("managed browser widened public URL scope")
	}
	if _, err = d.ServiceBrowserSession(t.Context(), later, redemption.CookieSecret, false, now); err == nil {
		t.Fatal("browser session widened to a later run")
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, r.TeamID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	current := read(a.Subject)
	if _, err := visitortoken.VerifyBearer(browserPermission.Token, current, now); err == nil {
		t.Fatal("suspension retained the signed-in visitor")
	}
	if _, err := visitortoken.VerifyBearer(grant.Token, current, now); err == nil {
		t.Fatal("suspension retained the explicit grant")
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
