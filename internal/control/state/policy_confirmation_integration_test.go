package state

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherRenewalConfirmsOnlyCurrentPolicy(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	d, at := f.database, f.now
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, at); err != nil {
		t.Fatal(err)
	}
	lease, err := visitorlease.New(scope, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	fetch := func() controlv1.VisitorPolicyUpdate {
		t.Helper()
		observation := lease.Begin()
		body, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.Apply(observation, decoded); err != nil {
			t.Fatal(err)
		}
		return body
	}
	first := fetch()
	if first.ConfirmationKey == nil {
		t.Fatal("quiet snapshot did not bind a confirmation key")
	}
	renew := func() *controlv1.PublisherPolicyConfirmation {
		t.Helper()
		state, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil {
			t.Fatal(err)
		}
		return state.PolicyConfirmation
	}
	at = at.Add(time.Second)
	observation := lease.Begin()
	evidence := renew()
	if evidence == nil || evidence.ConfirmationKey != *first.ConfirmationKey || !evidence.ValidUntil.After(first.Policy.ValidUntil) ||
		lease.Confirm(observation, *evidence) != nil {
		t.Fatal("new run renewal did not confirm the unchanged snapshot", evidence)
	}
	if _, err := d.pool.Exec(ctx, `SELECT control.touch_visitor_policy($1)`, scope.ID); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Second)
	observation = lease.Begin()
	changed := renew()
	if changed == nil || changed.ConfirmationKey == evidence.ConfirmationKey || lease.Confirm(observation, *changed) == nil {
		t.Fatal("a changed permission was confirmed as unchanged")
	}
	after, _, _ := lease.Current()
	if !after.ValidUntil.Equal(evidence.ValidUntil) {
		t.Fatal("rejected confirmation moved an accepted deadline")
	}
	if current := fetch(); current.ConfirmationKey == nil || *current.ConfirmationKey != changed.ConfirmationKey {
		t.Fatal("fresh snapshot did not catch up")
	}
	if err := d.RevokePublisherGrant(ctx, f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.publisher.CreatorID, at); err != nil {
		t.Fatal(err)
	}
	state, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err == nil || state.PolicyConfirmation != nil {
		t.Fatal("revoked run received new permission authority")
	}
}

func TestIntegrationPublisherRenewalCannotExtendRegisteredKeyParent(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	ctx := t.Context()
	r, _ := managementRegistration(t, f.setup.DeploymentScope, f.now)
	r.Permissions = map[string][]string{"connect": {"db"}}
	if _, err := f.d.RegisterDeploymentCredential(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := f.d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.run.ServiceID}
	policy, err := f.d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
	if err != nil || len(policy.Policy.RegisteredKeyLeases) != 1 || policy.ConfirmationKey != nil {
		t.Fatal("registered-key parent received an unchanged confirmation key", err)
	}
	state, err := f.d.HeartbeatServiceRun(ctx, f.run.ServiceID, f.run.RunID, f.run.Token, f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || state.PolicyConfirmation != nil {
		t.Fatal("run renewal extended a registered-key lease without a full authority read", err)
	}
}
