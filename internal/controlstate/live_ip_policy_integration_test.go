package controlstate

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ippolicy"
)

func TestIntegrationLiveIPChangesKeepRunAndExpireOperatorAccess(t *testing.T) {
	f := newPublishRunFixture(t)
	ingress := registerTestIngress(t, f.database, f.now)
	readyTestSession(t, f)
	route, err := f.database.GetPublicURLForAuthorization(t.Context(), f.setup.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	policyAt := func(at time.Time) ippolicy.Policy {
		t.Helper()
		snapshot, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, at)
		if err != nil || len(snapshot.Entries) != 1 {
			t.Fatalf("live routing projection = %d entries, %v", len(snapshot.Entries), err)
		}
		projection := snapshot.Entries[0].Projection
		if projection.PublishRunID != f.setup.PublishRunID || projection.IPPolicy != IPPolicyHashedAllowlist {
			t.Fatalf("IP policy changed the ready run: %+v", projection)
		}
		policy, err := ippolicy.New(projection.IPPolicyKey, projection.AllowedIPHashes)
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	change := LiveIPPolicyChange{PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		ActingIdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: route.MutationRevision}
	source := []string{"192.0.2.7/32"}
	change.Source = &source
	updated, _, err := f.database.ChangeLiveIPPolicy(t.Context(), change, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sourceIP := netip.MustParseAddr("192.0.2.7")
	operatorIP := netip.MustParseAddr("198.51.100.10")
	if policy := policyAt(f.now.Add(time.Second)); !policy.AllowsAt(sourceIP, f.now.Add(time.Second)) || policy.AllowsAt(operatorIP, f.now.Add(time.Second)) {
		t.Fatal("durable source entry was not published to ingress")
	}
	change.Source, change.ExpectedMutationRevision = nil, updated.MutationRevision
	change.AddOperator, change.OperatorLifetime = "198.51.100.10", time.Minute
	updated, issued, err := f.database.ChangeLiveIPPolicy(t.Context(), change, f.now.Add(2*time.Second))
	if err != nil || issued == nil {
		t.Fatalf("operator grant: %v", err)
	}
	policy := policyAt(f.now.Add(2 * time.Second))
	before, at, sourceLater := policy.AllowsAt(operatorIP, issued.ExpiresAt.Add(-time.Nanosecond)),
		policy.AllowsAt(operatorIP, issued.ExpiresAt), policy.AllowsAt(sourceIP, issued.ExpiresAt.Add(time.Minute))
	if !before || at || !sourceLater {
		t.Fatalf("ingress expiry: allowed before=%t at=%t source afterward=%t", before, at, sourceLater)
	}
	var ciphertext []byte
	if err := f.database.pool.QueryRow(t.Context(), `SELECT allowed_ip_policy_ciphertext FROM control.public_urls WHERE id = $1`,
		f.setup.PublicURLID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte(issued.Prefix)) {
		t.Fatalf("operator visitor IP was not sealed: %v", err)
	}
	change.AddOperator, change.RevokeOperatorID = "", issued.ID
	change.ExpectedMutationRevision = updated.MutationRevision
	updated, _, err = f.database.ChangeLiveIPPolicy(t.Context(), change, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if policy := policyAt(f.now.Add(3 * time.Second)); policy.AllowsAt(operatorIP, f.now.Add(3*time.Second)) ||
		!policy.AllowsAt(sourceIP, f.now.Add(3*time.Second)) {
		t.Fatal("revocation did not update ingress while preserving source access")
	}
	change.RevokeOperatorID, change.AddOperator = "", "198.51.100.10"
	change.ExpectedMutationRevision = updated.MutationRevision
	_, _, err = f.database.ChangeLiveIPPolicy(t.Context(), change, f.now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	count, err := f.database.ExpireOperatorIPEntries(t.Context(), f.now.Add(2*time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("expired operator entries = %d, %v", count, err)
	}
	remaining, err := f.database.ListOperatorIPEntries(t.Context(), f.setup.PublicURLID, f.now.Add(2*time.Minute))
	if err != nil || len(remaining) != 0 {
		t.Fatalf("operator entries after expiry = %d, %v", len(remaining), err)
	}
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.publish_runs WHERE id = $1`,
		f.setup.PublishRunID).Scan(&closed); err != nil || closed {
		t.Fatalf("live visitor IP edits closed the existing run: %t, %v", closed, err)
	}
}

func TestIntegrationSavedURLTargetEditKeepsOperatorIPTemporary(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "source_policy")
	seedControlPublicURL(t, database, now, "source")
	const id = "public_url_source"
	change := LiveIPPolicyChange{PublicURLID: id, TeamID: "team_source", ActingIdentityID: "identity_source",
		PolicyRevision: 1, ExpectedMutationRevision: 1}
	source := []string{"192.0.2.7/32"}
	change.Source = &source
	updated, _, err := database.ChangeLiveIPPolicy(t.Context(), change, now)
	if err != nil {
		t.Fatal(err)
	}
	change.Source, change.AddOperator = nil, "198.51.100.10"
	change.OperatorLifetime, change.ExpectedMutationRevision = time.Minute, updated.MutationRevision
	if _, _, err := database.ChangeLiveIPPolicy(t.Context(), change, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.GetPublicURLForAuthorization(t.Context(), id)
	if err != nil || len(loaded.AllowedIPPrefixes) != 1 || loaded.AllowedIPPrefixes[0].String() != source[0] {
		t.Fatalf("saved source IPs included the temporary operator entry: %v", err)
	}
	updated, err = database.UpdateAuthorizedPublicURL(t.Context(), AuthorizedPublicURLUpdateRequest{
		PublicURLID: id, TeamID: change.TeamID, ActingIdentityID: change.ActingIdentityID,
		Target: loaded.Target, AllowedIPPrefixes: source, PolicyRevision: 1,
		ExpectedMutationRevision: loaded.MutationRevision,
	}, now.Add(2*time.Second))
	if err != nil || len(updated.AllowedIPPrefixes) != 1 || updated.AllowedIPPrefixes[0].String() != source[0] {
		t.Fatalf("target edit changed durable source IPs: %v", err)
	}
	entries, err := database.ListOperatorIPEntries(t.Context(), id, now.Add(2*time.Second))
	if err != nil || len(entries) != 1 {
		t.Fatalf("target edit lost operator entry: %d, %v", len(entries), err)
	}
	if count, err := database.ExpireOperatorIPEntries(t.Context(), now.Add(2*time.Minute)); err != nil || count != 1 {
		t.Fatalf("operator IP did not expire after target edit: %d, %v", count, err)
	}
}
