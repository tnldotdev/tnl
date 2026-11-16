package state

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationServiceRunProtocolIsCapturedRequiredSupportedAndImmutable(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	q := controlstatedb.New(f.database.pool)
	original, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil || original.Protocol != "http" {
		t.Fatal("preparation did not capture the locked service protocol", original.Protocol, err)
	}
	if _, err := f.database.pool.Exec(ctx, `UPDATE control.service_runs SET protocol=protocol WHERE id=$1`, f.run.RunID); err != nil {
		t.Fatal("unchanged captured protocol blocked an ordinary run update", err)
	}
	_, err = f.database.pool.Exec(ctx, `UPDATE control.service_runs SET protocol='postgres' WHERE id=$1`, f.run.RunID)
	var immutable *pgconn.PgError
	if !errors.As(err, &immutable) || immutable.Code != "23514" || immutable.Message != "service run protocol is immutable" {
		t.Fatal("captured protocol was mutable", err)
	}
	// copy the real fixture's writable columns, rather than duplicate its run
	// constructor or rely on another missing field to reject the insert.
	var columns string
	if err := f.database.pool.QueryRow(ctx, `SELECT string_agg(quote_ident(attname),',' ORDER BY attnum)
	    FROM pg_attribute WHERE attrelid='control.service_runs'::regclass AND attnum>0
	      AND NOT attisdropped AND attgenerated='' AND attname<>'protocol'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	_, err = f.database.pool.Exec(ctx, `INSERT INTO control.service_runs (`+columns+`) SELECT `+columns+` FROM control.service_runs WHERE id=$1`, f.run.RunID)
	var missing *pgconn.PgError
	if !errors.As(err, &missing) || missing.Code != "23502" || missing.ColumnName != "protocol" {
		t.Fatal("omitted captured protocol acquired a default or failed for another field", err)
	}
	for _, protocol := range []string{"", "ssh", "HTTP"} {
		_, err := f.database.pool.Exec(ctx, `INSERT INTO control.service_runs (protocol,`+columns+`) SELECT $2,`+columns+` FROM control.service_runs WHERE id=$1`, f.run.RunID, protocol)
		var unsupported *pgconn.PgError
		if !errors.As(err, &unsupported) || unsupported.Code != "23514" || unsupported.ConstraintName != "service_runs_protocol_check" {
			t.Fatal("unsupported captured protocol was accepted or failed for another constraint", protocol, err)
		}
	}
	current, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil || current.Protocol != original.Protocol {
		t.Fatal("rejected changes replaced the original run protocol", current.Protocol, err)
	}
}

func TestIntegrationNativeRunCannotSubmitPairlessHTTPAuditAfterHTTPDefinition(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx := t.Context()
	actor := f.actor(t)
	nativeMetadata := f.service.ServiceMetadata
	nativeMetadata.Protocol = "postgres"
	native, err := f.database.ConfigureService(ctx, f.service.ID, actor, nativeMetadata,
		&ProjectServiceConfiguration{Protocol: "postgres", Target: "database.internal:5432"},
		ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	nativePublication := servicePublicationFixture{database: f.database, now: f.now.Add(time.Second), service: native, publisher: f.publisher, leases: f.leases}
	nativePublication.start(t, "native-audit", f.now.Add(time.Second))
	installPrivateTestCertificate(t, f.database, nativePublication.prepared, nativePublication.run, f.now.Add(time.Second))
	nativePublication.readyConnections(t, f.now.Add(time.Second))
	if _, err := f.database.HeartbeatServiceRun(ctx, native.ID, nativePublication.run.RunID, nativePublication.run.Token, f.now.Add(time.Second),
		ServiceRunHealth{Healthy: true, StreamCapacity: 16}); err != nil {
		t.Fatal(err)
	}
	restoredMetadata := native.ServiceMetadata
	restoredMetadata.Protocol = "http"
	if _, err := f.database.ConfigureService(ctx, native.ID, actor, restoredMetadata,
		&ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"}, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	captured, err := controlstatedb.New(f.database.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: nativePublication.run.RunID, ServiceID: native.ID})
	if err != nil || captured.Protocol != "postgres" || !captured.ReadyAt.Valid || !captured.ClosedAt.Valid {
		t.Fatal("HTTP definition changed the old native run's captured protocol or lifetime", captured.Protocol, err)
	}
	event := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: native.ID, ServiceKind: "service",
		RunID: nativePublication.run.RunID, RunNumber: nativePublication.run.RunNumber,
		VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), SourceIP: "192.0.2.10",
		EventType: "connection.open", Outcome: "allowed", OccurredAt: f.now.Add(time.Second)}
	result, err := f.database.IngestServiceRunObservations(ctx, native.ID, nativePublication.run.RunID,
		nativePublication.run.Token, nativePublication.run.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{event}}, f.now.Add(3*time.Second))
	if !errors.Is(err, ErrServiceAuditAccess) || result != (ServiceObservationResult{}) {
		t.Fatal("current HTTP definition let a native run bypass its connector pair/source binding", result, err)
	}
	var retained int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1`, event.EventID).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("rejected pairless native report left an audit event", retained, err)
	}
	for range 2 {
		if err := f.database.CloseServiceRun(ctx, native.ID, nativePublication.run.RunID, nativePublication.run.Token, f.now.Add(3*time.Second)); err != nil {
			t.Fatal("captured native audit restriction gated independent exact-token cleanup", err)
		}
	}
}
