package state

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationVisitorPolicyRegisteredKeyCandidates(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	ctx := t.Context()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.deployment.Services["db"].ID}
	if err := f.d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}

	type registeredKey struct {
		credential DeploymentCredential
		public     ed25519.PublicKey
	}
	active := make(map[string]registeredKey, 256)
	check := func(t *testing.T, observed time.Time, wantCandidates bool, wantCount int) {
		t.Helper()
		tx, err := f.d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := tx.Rollback(ctx); err != nil {
				t.Error(err)
			}
		})
		q := controlstatedb.New(tx)
		possible, err := q.HasVisitorPolicyRegisteredKeyCandidates(ctx, scope.ID)
		if err != nil || possible != wantCandidates {
			t.Fatalf("candidate check = %t, %v; want %t", possible, err, wantCandidates)
		}
		full, err := q.ReadVisitorPolicyRegisteredKeys(ctx, controlstatedb.ReadVisitorPolicyRegisteredKeysParams{
			ServiceID: scope.ID, AtTime: timestamptz(observed),
		})
		if err != nil {
			t.Fatal(err)
		}
		policy, err := f.d.readVisitorPolicy(ctx, tx, scope, 0, observed)
		if err != nil {
			t.Fatal(err)
		}
		leases := policy.Policy.RegisteredKeyLeases
		if len(full) != wantCount || leases == nil || len(leases) != len(full) {
			t.Fatalf("full lookup = %d; policy = %d; want %d", len(full), len(leases), wantCount)
		}
		for i, key := range full {
			want, found := active[key.GrantID]
			if !found || key.KeyID != want.credential.KeyID || !bytes.Equal(key.PublicKey, want.public) {
				t.Fatalf("full lookup returned an unexpected grant/key at index %d", i)
			}
			until := minTime(want.credential.ExpiresAt, observed.Add(90*time.Second))
			digest, err := visitortoken.KeyDigest(want.public)
			if err != nil {
				t.Fatal(err)
			}
			got := leases[i]
			if !key.ExpiresAt.Time.Equal(until) || got.GrantId != key.GrantID || got.KeyId != key.KeyID ||
				got.KeySha256 != digest || !got.ExpiresAt.Equal(until) {
				t.Fatalf("policy returned an unexpected grant, key, or expiry at index %d", i)
			}
		}
	}

	manage, _ := managementRegistration(t, f.setup.DeploymentScope, f.now)
	if _, err := f.d.RegisterDeploymentCredential(ctx, manage); err != nil {
		t.Fatal(err)
	}
	t.Run("no connect grants", func(t *testing.T) { check(t, f.now, false, 0) })
	var first DeploymentCredential
	for i := range 256 {
		request, _ := managementRegistration(t, f.setup.DeploymentScope, f.now)
		request.Name = fmt.Sprintf("policy-key-%d", i)
		request.IdempotencyKey = request.Name
		request.Permissions = map[string][]string{"connect": {"db"}}
		credential, err := f.d.RegisterDeploymentCredential(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		active[credential.GrantID] = registeredKey{credential, request.PublicKey}
		if i == 0 {
			first = credential
		}
		if i == 3 {
			t.Run("four connect grants", func(t *testing.T) { check(t, f.now, true, 4) })
		}
	}
	t.Run("256 connect grants", func(t *testing.T) { check(t, f.now, true, 256) })
	if err := f.d.RevokePublisherGrant(ctx, f.setup.TeamID, first.ClientID, first.GrantID, f.setup.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	delete(active, first.GrantID)
	t.Run("revoked", func(t *testing.T) { check(t, f.now, true, 255) })
	t.Run("near expiry", func(t *testing.T) { check(t, first.ExpiresAt.Add(-time.Second), true, 255) })
	t.Run("expired", func(t *testing.T) { check(t, first.ExpiresAt, true, 0) })
}
