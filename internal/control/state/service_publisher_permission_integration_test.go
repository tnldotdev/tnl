package state

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationExactPublisherPermissionDoesNotPlanDeploymentBranches(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	d, ctx := f.database, t.Context()
	var publisher, grant string
	if err := d.pool.QueryRow(ctx, `SELECT publisher_identity_id,publisher_grant_id
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&publisher, &grant); err != nil {
		t.Fatal(err)
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `LOCK TABLE control.deployments,control.deployment_management_services IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	check, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var deadline pgtype.Timestamptz
	if err := d.pool.QueryRow(check, `SELECT expires_at FROM control.publisher_service_permission($1,$2,$3,$4)`,
		publisher, grant, f.service.ID, f.now).Scan(&deadline); err != nil {
		t.Fatal("an exact service grant planned an unrelated deployment branch", err)
	}
}

func TestIntegrationPublisherPermissionRetainsSnapshotAndPlanningBoundary(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	d, ctx := f.database, t.Context()
	var publisher, grant, signing string
	if err := d.pool.QueryRow(ctx, `SELECT publisher_identity_id,publisher_grant_id,publisher_key_id
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&publisher, &grant, &signing); err != nil {
		t.Fatal(err)
	}
	// replica refreshes must call the bounded permission query, not expand every
	// namespace/deployment branch into their own freshly planned statement.
	var encoded []byte
	if err := d.pool.QueryRow(ctx, `EXPLAIN (FORMAT JSON)
		SELECT * FROM control.publisher_service_permission($1,$2,$3,$4)`,
		publisher, grant, f.service.ID, f.now).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var plans []struct {
		Plan struct {
			NodeType string `json:"Node Type"`
			Function string `json:"Function Name"`
			Rows     int    `json:"Plan Rows"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal(encoded, &plans); err != nil || len(plans) != 1 ||
		plans[0].Plan.NodeType != "Function Scan" || plans[0].Plan.Function != "publisher_service_permission" || plans[0].Plan.Rows != 1 {
		t.Fatal("publisher permission lost its single-result planning boundary", string(encoded), err)
	}
	reader, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, reader)
	request := controlstatedb.GetServiceRunPublisherIdentityParams{
		Now: timestamptz(f.now), ID: f.run.RunID, RunNumber: f.run.RunNumber, ServiceID: f.service.ID,
		PublisherIdentityID: publisher, PublisherGrantID: grant, PublisherKeyID: signing,
	}
	if _, err := controlstatedb.New(reader).GetServiceRunPublisherIdentity(ctx, request); err != nil {
		t.Fatal("permission did not authorize its exact persisted publisher tuple", err)
	}
	var before pgtype.Timestamptz
	if err := reader.QueryRow(ctx, `SELECT expires_at FROM control.publisher_service_permission($1,$2,$3,$4)`,
		publisher, grant, f.service.ID, f.now).Scan(&before); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(time.Second)
	if err := d.RevokePublisherGrant(ctx, f.service.TeamID, publisher, grant, f.project.ActorID, at); err != nil {
		t.Fatal(err)
	}
	var after pgtype.Timestamptz
	if err := reader.QueryRow(ctx, `SELECT expires_at FROM control.publisher_service_permission($1,$2,$3,$4)`,
		publisher, grant, f.service.ID, at).Scan(&after); err != nil || before != after {
		t.Fatal("permission escaped its caller's authority snapshot or changed its deadline", err)
	}
	if _, err := controlstatedb.New(reader).GetServiceRunPublisherIdentity(ctx, request); err != nil {
		t.Fatal("replica query mixed authority snapshots", err)
	}
	request.Now = timestamptz(at)
	if _, err := controlstatedb.New(d.pool).GetServiceRunPublisherIdentity(ctx, request); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("a fresh replica query retained a revoked publisher grant", err)
	}
}
