package state

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationAliasWatchIsolatesSiblingsAndRetainsSharedChanges(t *testing.T) {
	f, _, _ := newRunAliasServiceFixture(t)
	d, ctx := f.database, t.Context()
	a, b := f.publish(t, f.service), f.publish(t, f.service)
	compare := func(seen ...ConnectorPeerWatchVersion) []ConnectorPeerWatchVersion {
		t.Helper()
		changed, err := d.CompareConnectorPeerWatchVersions(ctx, seen)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	initial := func(r ServiceRunState) ConnectorPeerWatchVersion {
		t.Helper()
		hints := compare(ConnectorPeerWatchVersion{RunID: r.RunID, Revision: -1})
		if len(hints) != 1 || !controlv1.ValidPublisherPolicyBookmark(hints[0].PolicyBookmark) {
			t.Fatal("missing initial policy hint")
		}
		return hints[0]
	}
	seenA, seenB := initial(a), initial(b)
	if err := d.CloseServiceRun(ctx, a.ServiceID, a.RunID, a.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if changed := compare(seenA, seenB); len(changed) != 1 || changed[0].RunID != a.RunID || changed[0].Revision != -1 {
		t.Fatal("closing an alias disturbed its sibling", changed)
	}
	c := f.publish(t, f.service)
	if changed := compare(seenB); len(changed) != 0 {
		t.Fatal("new alias disturbed its sibling", changed)
	}
	seenC := initial(c)
	if _, err := d.pool.Exec(ctx, `SELECT control.touch_visitor_policy($1)`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	changes := compare(seenB, seenC)
	if len(changes) != 2 {
		t.Fatal("shared policy failed to reach both survivors", changes)
	}
	for _, change := range changes {
		if change.Revision < 0 || change.PolicyBookmark == seenB.PolicyBookmark || change.PolicyBookmark == seenC.PolicyBookmark {
			t.Fatal("shared policy did not produce fresh live bookmarks")
		}
	}
}

func TestIntegrationPolicyWatchFollowsWorkloadParent(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_watch")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	request, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0].ServiceID
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	before := policyObservation(t, d, scope, 0).Policy
	if len(before.WorkloadLeases) != 1 || before.WorkloadLeases[0].SessionId != session.ID {
		t.Fatal("missing original workload")
	}
	bookmark := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT bookmark FROM control.service_policy_watch_bookmarks WHERE service_id=$1`, service).Scan(&value); err != nil || !controlv1.ValidPublisherPolicyBookmark(value) {
			t.Fatal("missing bookmark", err)
		}
		return value
	}
	start := bookmark()
	renewed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), now.Add(31*time.Second))
	if err != nil || !renewed.LeaseExpiresAt.After(session.LeaseExpiresAt) {
		t.Fatal("failed to renew with the original credential", err)
	}
	next := bookmark()
	if next == start || policyRevision(t, d, scope) != before.VisitorPolicyRevision {
		t.Fatal("workload renewal was lost or invalidated unrelated signed permissions")
	}
	if err := d.RevokeWorkloadSession(ctx, session.ID, session.Credential, now.Add(32*time.Second)); err != nil {
		t.Fatal(err)
	}
	if bookmark() == next || len(policyObservation(t, d, scope, 0).Policy.WorkloadLeases) != 0 {
		t.Fatal("revocation did not reach the watch and the snapshot together")
	}
}
