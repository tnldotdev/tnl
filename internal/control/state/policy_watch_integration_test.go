package state

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPolicyWatchFollowsWorkloadParentAcrossMigration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_watch")
	ctx := t.Context()
	direct, migrations := watchMigrationFixture(t, d)
	if _, err := migrations.DownTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
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
	if err := Migrate(ctx, direct); err != nil {
		t.Fatal(err)
	}
	bookmark := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT bookmark FROM control.publisher_policy_watch_bookmarks WHERE service_id=$1`, service).Scan(&value); err != nil || !controlv1.ValidPublisherPolicyBookmark(value) {
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
