package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationRegisteredKeyWatchTracksAuthorityInputs(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	ctx := t.Context()
	service := f.deployment.Services["db"].ID
	read := func(t *testing.T, q *controlstatedb.Queries, id string) controlstatedb.ReadRegisteredKeyWatchVersionRow {
		t.Helper()
		v, err := q.ReadRegisteredKeyWatchVersion(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	outside := controlstatedb.New(f.d.pool)
	initial := read(t, outside, service)
	r, _ := managementRegistration(t, f.setup.DeploymentScope, f.now)
	r.AllDeployments, r.DeploymentIDs = false, []string{f.deployment.ID}
	r.Permissions = map[string][]string{"manage": {"web"}, "connect": {"db"}}
	cred, err := f.d.RegisterDeploymentCredential(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	before := read(t, outside, service)
	if before == initial {
		t.Fatal("first connect grant did not advance its service's bookmark")
	}
	full := func(t *testing.T, q *controlstatedb.Queries, want int) {
		t.Helper()
		keys, err := q.ReadVisitorPolicyRegisteredKeys(ctx, controlstatedb.ReadVisitorPolicyRegisteredKeysParams{ServiceID: service, AtTime: timestamptz(f.now)})
		if err != nil || len(keys) != want || want == 1 && (keys[0].GrantID != cred.GrantID || keys[0].KeyID != cred.KeyID) {
			t.Fatalf("authorized keys: got %d, want %d: %v", len(keys), want, err)
		}
	}
	full(t, outside, 1)
	for _, mutation := range []struct {
		name, query string
		args        []any
	}{
		{"grant", `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, []any{cred.GrantID, f.now}},
		{"identity", `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, []any{cred.ClientID, f.now}},
		{"key", `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, []any{cred.KeyID, f.now}},
		{"connect selection", `DELETE FROM control.deployment_management_services WHERE grant_id=$1 AND capability='connect'`, []any{cred.GrantID}},
		{"other required selection", `UPDATE control.deployment_management_services SET revoked_at=$2 WHERE grant_id=$1 AND capability='manage'`, []any{cred.GrantID, f.now}},
		{"deployment selection", `DELETE FROM control.deployment_management_deployments WHERE grant_id=$1`, []any{cred.GrantID}},
		{"deployment", `UPDATE control.deployments SET deleted_at=$2 WHERE id=$1`, []any{f.deployment.ID, f.now}},
		{"team", `UPDATE control.teams SET deleted_at=$2 WHERE id=$1`, []any{f.setup.TeamID, f.now}},
		{"service binding", `UPDATE control.applied_project_services SET service_id=NULL WHERE service_id=$1`, []any{service}},
		{"project declaration", `UPDATE control.project_services SET protocol='mysql' WHERE team_id=$1 AND project_key=$2 AND name='db'`, []any{f.setup.TeamID, f.setup.ProjectKey}},
		{"service", `UPDATE control.services SET enabled=false WHERE id=$1`, []any{service}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			tx, err := f.d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			if _, err := tx.Exec(ctx, mutation.query, mutation.args...); err != nil {
				t.Fatal(err)
			}
			q := controlstatedb.New(tx)
			full(t, q, 0)
			if read(t, q, service) == before || read(t, outside, service) != before {
				t.Fatal("bookmark and permissions did not change in the same transaction")
			}
		})
	}
	// both commits finish before the subscriber returns. the final authorized
	// grant is identical, but history cannot be reported as unchanged.
	for _, query := range []string{
		`UPDATE control.deployment_management_services SET revoked_at=now() WHERE grant_id=$1 AND capability='manage'`,
		`UPDATE control.deployment_management_services SET revoked_at=NULL WHERE grant_id=$1 AND capability='manage'`,
	} {
		if _, err := f.d.pool.Exec(ctx, query, cred.GrantID); err != nil {
			t.Fatal(err)
		}
	}
	full(t, outside, 1)
	if read(t, outside, service).ProjectRevision <= before.ProjectRevision {
		t.Fatal("coalesced revoke/regrant returned the original bookmark")
	}
}

func TestIntegrationRegisteredKeyWatchMigratesPopulatedVersionTwo(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	ctx := t.Context()
	service := f.deployment.Services["db"].ID
	direct, migrations := watchMigrationFixture(t, f.d)
	if _, err := migrations.DownTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	r, private := managementRegistration(t, f.setup.DeploymentScope, f.now)
	r.Permissions = map[string][]string{"connect": {"db"}}
	cred, err := f.d.RegisterDeploymentCredential(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(f.d.pool)
	params := controlstatedb.ReadVisitorPolicyRegisteredKeysParams{ServiceID: service, AtTime: timestamptz(f.now)}
	before, err := q.ReadVisitorPolicyRegisteredKeys(ctx, params)
	if err != nil || len(before) != 1 {
		t.Fatal("missing pre-upgrade registered key", err)
	}
	if err := Migrate(ctx, direct); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := q.ReadVisitorPolicyRegisteredKeys(ctx, params)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("migration changed an existing registered key, grant, or expiry", err)
	}
	_ = managementAccess(t, f.d, cred, private, f.now)
	v, err := q.ReadRegisteredKeyWatchVersion(ctx, service)
	if err != nil || v != (controlstatedb.ReadRegisteredKeyWatchVersionRow{}) {
		t.Fatal("migration invented a change for an existing binding", err)
	}
	params.AtTime = timestamptz(f.now.Add(time.Second))
	renewed, err := q.ReadVisitorPolicyRegisteredKeys(ctx, params)
	if err != nil || len(renewed) != 1 || !renewed[0].ExpiresAt.Time.Equal(before[0].ExpiresAt.Time.Add(time.Second)) {
		t.Fatal("an unchanged key still needs a fresh lease observation", err)
	}
	if err := f.d.RevokePublisherGrant(ctx, f.setup.TeamID, cred.ClientID, cred.GrantID, f.setup.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if next, err := q.ReadRegisteredKeyWatchVersion(ctx, service); err != nil || next == v {
		t.Fatal("first revocation after upgrade did not change the bookmark", err)
	}
}
