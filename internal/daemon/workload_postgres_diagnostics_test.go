package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	workloadPostgresDiagnosticTimeout = 2 * time.Second
	workloadPostgresDiagnosticBytes   = 8 << 10
	workloadPostgresDiagnosticPairs   = 1
	workloadPostgresDiagnosticClaims  = 4
	workloadPostgresDiagnosticLimits  = "saved control state only; publisher report receive time and component-local authority, permission, and packet state unavailable; backend may have exited after query timeout"
)

type workloadPostgresDiagnosticScope struct {
	WorkloadSessionID string `json:"workload_session_id"`
	Service           string `json:"project_service"`
	ServiceID         string `json:"service_id"`
	ServiceRunID      string `json:"service_run_id"`
	PairID            string `json:"pair_id"`
	RunNumber         uint64 `json:"run_number"`
	BackendPID        uint32 `json:"retained_backend_pid"`
}

type workloadPostgresDiagnosticSource struct {
	inspect *sql.DB
	scope   workloadPostgresDiagnosticScope
	pair    atomic.Pointer[workloadPostgresPairIdentity]
}

type workloadPostgresPairIdentity struct {
	id, runID string
	runNumber uint64
}

// retain only the actual prepared pair's identity, not its secrets or the
// earlier preflight selection. background renewals and arrivals are unchanged.
type workloadPostgresDiagnosticControl struct {
	connectorstream.Control
	source *workloadPostgresDiagnosticSource
}

func (c workloadPostgresDiagnosticControl) PrepareConnectorPeerPair(ctx context.Context, service string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	pair, err := c.Control.PrepareConnectorPeerPair(ctx, service, request)
	if err == nil {
		c.source.pair.Store(&workloadPostgresPairIdentity{id: pair.PairId, runID: pair.ServiceRunId, runNumber: uint64(pair.RunNumber)})
	}
	return pair, err
}

// the original native query has already failed. read through the fixture's
// independent inspection pool before Fatal cancels the connector owners; never
// use the failed application's connection or inherit its spent query context.
func (d *workloadPostgresDiagnosticSource) log(t *testing.T) {
	t.Helper()
	if d == nil {
		t.Log("native PostgreSQL failure-time snapshot unavailable: no retained backend scope")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), workloadPostgresDiagnosticTimeout)
	defer cancel()
	scope := d.scope
	if pair := d.pair.Load(); pair != nil {
		scope.PairID, scope.ServiceRunID, scope.RunNumber = pair.id, pair.runID, pair.runNumber
	}
	var raw []byte
	err := d.inspect.QueryRowContext(ctx, workloadPostgresDiagnosticQuery,
		scope.WorkloadSessionID, scope.ServiceID, scope.ServiceRunID, scope.RunNumber, scope.BackendPID, scope.PairID).Scan(&raw)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	t.Logf("native PostgreSQL failure-time snapshot: %s", formatWorkloadPostgresDiagnostic(scope, raw, err))
}

// one statement observes the exact pair/source/service/run, without locks or
// authority mutations. the extra claim is only an overflow sentinel. SQL selects no
// credentials, packet keys, source payloads, target addresses, or query text.
const workloadPostgresDiagnosticQuery = `WITH selected_pairs AS (
	SELECT id,delivery_generation,high_water_generation,last_authorized_at,expires_at,
		publisher_prepared_until,publisher_proved_until,rebind_operation_id,rebind_generation,rebind_status
	FROM control.connector_peer_pairs
	WHERE subject_kind='workload_session' AND subject_id=$1 AND service_id=$2 AND service_run_id=$3 AND run_number=$4 AND id=$6
	LIMIT 1
)
SELECT jsonb_build_object(
	'observed_at',statement_timestamp(),
	'workload_authority',(SELECT jsonb_build_object(
		'lease_expires_at',lease_expires_at,'identity_proof_expires_at',identity_expires_at,
		'hard_expires_at',expires_at,'renewed_at',renewed_at,'renewal_sequence',renewal_sequence,'revoked_at',revoked_at)
		FROM control.workload_sessions WHERE id=$1),
	'pairs',COALESCE((SELECT jsonb_agg(jsonb_build_object(
		'pair_id',pair.id,'active_delivery_generation',pair.delivery_generation,'high_water_generation',pair.high_water_generation,
		'last_authorized_at',pair.last_authorized_at,'expires_at',pair.expires_at,
		'publisher_prepared_until',pair.publisher_prepared_until,'publisher_proved_until',pair.publisher_proved_until,
		'rebind_operation_id',left(pair.rebind_operation_id,128),'rebind_generation',pair.rebind_generation,'rebind_status',left(pair.rebind_status,64),
		'pending_binding',(SELECT jsonb_build_object('operation_id',pending.operation_id,'delivery_generation',pending.delivery_generation,
			'created_at',pending.created_at,'pending_until',pending.pending_until,
			'publisher_prepared_until',pending.publisher_prepared_until,'publisher_proved_until',pending.publisher_proved_until)
			FROM control.connector_peer_pending_bindings pending WHERE pending.pair_id=pair.id),
		'leg_claims',COALESCE((SELECT jsonb_agg(jsonb_build_object('delivery_generation',claim.delivery_generation,
			'connection_slot',claim.connection_slot,'checked_at',claim.checked_at,'confirmed_until',claim.confirmed_until)
			ORDER BY claim.delivery_generation DESC,claim.connection_slot)
			FROM (SELECT delivery_generation,connection_slot,checked_at,confirmed_until
				FROM control.connector_peer_pair_leg_claims WHERE pair_id=pair.id
				ORDER BY delivery_generation DESC,connection_slot LIMIT 5) claim),'[]'::jsonb)) ORDER BY pair.id)
		FROM selected_pairs pair),'[]'::jsonb),
	'backend',(SELECT jsonb_build_object('state',left(state,64),'wait_event_type',left(wait_event_type,64),'wait_event',left(wait_event,64),
		'backend_xid',backend_xid::text,'backend_xmin',backend_xmin::text,'transaction_started_at',xact_start)
		FROM pg_stat_activity WHERE pid=$5 AND datname=current_database()))`

type workloadPostgresDiagnosticReport struct {
	Scope      workloadPostgresDiagnosticScope        `json:"scope"`
	ReadStatus string                                 `json:"read_status"`
	Snapshot   *workloadPostgresDiagnosticObservation `json:"snapshot,omitempty"`
	Limits     string                                 `json:"limits"`
}

type workloadPostgresDiagnosticObservation struct {
	ObservedAt        time.Time                            `json:"observed_at"`
	WorkloadAuthority *workloadPostgresDiagnosticAuthority `json:"workload_authority"`
	Pairs             []workloadPostgresDiagnosticPair     `json:"pairs"`
	PairsOmitted      bool                                 `json:"pairs_omitted"`
	Backend           *workloadPostgresDiagnosticBackend   `json:"backend"`
}

type workloadPostgresDiagnosticAuthority struct {
	LeaseExpiresAt         time.Time  `json:"lease_expires_at"`
	IdentityProofExpiresAt time.Time  `json:"identity_proof_expires_at"`
	HardExpiresAt          *time.Time `json:"hard_expires_at"`
	RenewedAt              time.Time  `json:"renewed_at"`
	RenewalSequence        int64      `json:"renewal_sequence"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

type workloadPostgresDiagnosticPair struct {
	PairID                   string                             `json:"pair_id"`
	ActiveDeliveryGeneration int64                              `json:"active_delivery_generation"`
	HighWaterGeneration      int64                              `json:"high_water_generation"`
	LastAuthorizedAt         time.Time                          `json:"last_authorized_at"`
	ExpiresAt                time.Time                          `json:"expires_at"`
	PublisherPreparedUntil   *time.Time                         `json:"publisher_prepared_until"`
	PublisherProvedUntil     *time.Time                         `json:"publisher_proved_until"`
	RebindOperationID        string                             `json:"rebind_operation_id"`
	RebindGeneration         *int64                             `json:"rebind_generation"`
	RebindStatus             string                             `json:"rebind_status"`
	PendingBinding           *workloadPostgresDiagnosticPending `json:"pending_binding"`
	LegClaims                []workloadPostgresDiagnosticClaim  `json:"leg_claims"`
	ClaimsOmitted            bool                               `json:"claims_omitted"`
}

type workloadPostgresDiagnosticPending struct {
	OperationID            string     `json:"operation_id"`
	DeliveryGeneration     int64      `json:"delivery_generation"`
	CreatedAt              time.Time  `json:"created_at"`
	PendingUntil           time.Time  `json:"pending_until"`
	PublisherPreparedUntil *time.Time `json:"publisher_prepared_until"`
	PublisherProvedUntil   *time.Time `json:"publisher_proved_until"`
}

type workloadPostgresDiagnosticClaim struct {
	DeliveryGeneration int64     `json:"delivery_generation"`
	ConnectionSlot     int       `json:"connection_slot"`
	CheckedAt          time.Time `json:"checked_at"`
	ConfirmedUntil     time.Time `json:"confirmed_until"`
}

type workloadPostgresDiagnosticBackend struct {
	State                string     `json:"state"`
	WaitEventType        string     `json:"wait_event_type"`
	WaitEvent            string     `json:"wait_event"`
	BackendXID           string     `json:"backend_xid"`
	BackendXmin          string     `json:"backend_xmin"`
	TransactionStartedAt *time.Time `json:"transaction_started_at"`
}

// project only typed facts, not unknown JSON fields or driver error strings.
// explicit identifiers and bounded tokens also reject accidental payloads in
// text columns. missing backend rows and absent pending bindings remain null.
func formatWorkloadPostgresDiagnostic(scope workloadPostgresDiagnosticScope, raw []byte, readErr error) string {
	scope.WorkloadSessionID = workloadDiagnosticID(scope.WorkloadSessionID, "wls_")
	scope.ServiceID = workloadDiagnosticID(scope.ServiceID, opaqueid.ServicePrefix)
	scope.ServiceRunID = workloadDiagnosticID(scope.ServiceRunID, opaqueid.ServiceRunPrefix)
	scope.PairID = workloadDiagnosticID(scope.PairID, "cpp_")
	if !naming.ValidServiceName(scope.Service) {
		scope.Service = "<invalid>"
	}
	report := workloadPostgresDiagnosticReport{Scope: scope, ReadStatus: "ok", Limits: workloadPostgresDiagnosticLimits}
	switch {
	case errors.Is(readErr, context.DeadlineExceeded):
		report.ReadStatus = "timeout"
	case errors.Is(readErr, context.Canceled):
		report.ReadStatus = "canceled"
	case readErr != nil:
		report.ReadStatus = "unavailable"
	case len(raw) > 2*workloadPostgresDiagnosticBytes:
		report.ReadStatus = "oversized"
	default:
		var snapshot workloadPostgresDiagnosticObservation
		if err := json.Unmarshal(raw, &snapshot); err != nil || snapshot.ObservedAt.IsZero() {
			report.ReadStatus = "invalid"
			break
		}
		snapshot.PairsOmitted = len(snapshot.Pairs) > workloadPostgresDiagnosticPairs
		snapshot.Pairs = snapshot.Pairs[:min(len(snapshot.Pairs), workloadPostgresDiagnosticPairs)]
		for i := range snapshot.Pairs {
			pair := &snapshot.Pairs[i]
			pair.PairID = workloadDiagnosticID(pair.PairID, "cpp_")
			if pair.RebindOperationID != "" {
				pair.RebindOperationID = workloadDiagnosticID(pair.RebindOperationID, opaqueid.IdempotencyPrefix)
			}
			if !slices.Contains([]string{"", "pending", "active", "aborted", "expired"}, pair.RebindStatus) {
				pair.RebindStatus = "<invalid>"
			}
			if pair.PendingBinding != nil {
				pair.PendingBinding.OperationID = workloadDiagnosticID(pair.PendingBinding.OperationID, opaqueid.IdempotencyPrefix)
			}
			pair.ClaimsOmitted = len(pair.LegClaims) > workloadPostgresDiagnosticClaims
			pair.LegClaims = pair.LegClaims[:min(len(pair.LegClaims), workloadPostgresDiagnosticClaims)]
		}
		if backend := snapshot.Backend; backend != nil {
			if !slices.Contains([]string{"", "active", "idle", "idle in transaction", "idle in transaction (aborted)", "fastpath function call", "disabled"}, backend.State) {
				backend.State = "<invalid>"
			}
			backend.WaitEventType = workloadDiagnosticToken(backend.WaitEventType)
			backend.WaitEvent = workloadDiagnosticToken(backend.WaitEvent)
			for _, xid := range []*string{&backend.BackendXID, &backend.BackendXmin} {
				if _, err := strconv.ParseUint(*xid, 10, 32); *xid != "" && err != nil {
					*xid = "<invalid>"
				}
			}
		}
		report.Snapshot = &snapshot
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > workloadPostgresDiagnosticBytes {
		report.ReadStatus, report.Snapshot = "oversized", nil
		encoded, _ = json.Marshal(report)
	}
	return string(encoded)
}

func workloadDiagnosticID(value, prefix string) string {
	if !opaqueid.Valid(value, prefix) {
		return "<invalid>"
	}
	return value
}

func workloadDiagnosticToken(value string) string {
	if len(value) > 64 || strings.IndexFunc(value, func(r rune) bool {
		return r < 'A' || r > 'Z' && r < 'a' || r > 'z'
	}) >= 0 {
		return "<invalid>"
	}
	return value
}

func TestWorkloadPostgresDiagnosticProjection(t *testing.T) {
	scope := workloadPostgresDiagnosticScope{WorkloadSessionID: "wls_" + strings.Repeat("a", 22), Service: "db",
		ServiceID: "svc_" + strings.Repeat("b", 22), ServiceRunID: "srun_" + strings.Repeat("c", 22),
		PairID: "cpp_" + strings.Repeat("d", 22), RunNumber: 3, BackendPID: 42}
	now := time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC)
	operation := "ik_" + strings.Repeat("e", 22)
	expected := workloadPostgresDiagnosticObservation{ObservedAt: now,
		WorkloadAuthority: &workloadPostgresDiagnosticAuthority{LeaseExpiresAt: now.Add(time.Minute), IdentityProofExpiresAt: now.Add(2 * time.Minute), HardExpiresAt: new(now.Add(3 * time.Minute)), RenewedAt: now, RenewalSequence: 3},
		Pairs: []workloadPostgresDiagnosticPair{{PairID: scope.PairID, ActiveDeliveryGeneration: 7, HighWaterGeneration: 8,
			LastAuthorizedAt: now, ExpiresAt: now.Add(time.Minute), PublisherPreparedUntil: new(now.Add(30 * time.Second)),
			RebindOperationID: operation, RebindGeneration: new(int64(8)), RebindStatus: "pending",
			PendingBinding: &workloadPostgresDiagnosticPending{OperationID: operation, DeliveryGeneration: 8, CreatedAt: now, PendingUntil: now.Add(10 * time.Second), PublisherPreparedUntil: new(now.Add(9 * time.Second))},
			LegClaims: []workloadPostgresDiagnosticClaim{
				{DeliveryGeneration: 8, ConnectionSlot: 0, CheckedAt: now, ConfirmedUntil: now.Add(10 * time.Second)},
				{DeliveryGeneration: 7, ConnectionSlot: 1, CheckedAt: now.Add(-time.Second), ConfirmedUntil: now.Add(30 * time.Second)},
			}}},
		Backend: &workloadPostgresDiagnosticBackend{State: "idle in transaction", WaitEventType: "Client", WaitEvent: "ClientRead", BackendXID: "123", BackendXmin: "122", TransactionStartedAt: &now}}
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var withSecrets map[string]any
	if err := json.Unmarshal(raw, &withSecrets); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"wlc_private_credential", "eyJ.private.jwt", "SELECT private_target_payload", "postgres://user:password@private/db", "private-packet-key"}
	withSecrets["credential"], withSecrets["assertion"] = secrets[0], secrets[1]
	withSecrets["backend"].(map[string]any)["query"] = secrets[2]
	withSecrets["backend"].(map[string]any)["usename"] = secrets[3]
	withSecrets["pairs"].([]any)[0].(map[string]any)["key_ciphertext"] = secrets[4]
	raw, err = json.Marshal(withSecrets)
	if err != nil {
		t.Fatal(err)
	}
	encoded := formatWorkloadPostgresDiagnostic(scope, raw, nil)
	var report workloadPostgresDiagnosticReport
	if err := json.Unmarshal([]byte(encoded), &report); err != nil {
		t.Fatal(err)
	}
	if report.ReadStatus != "ok" || report.Scope != scope || !reflect.DeepEqual(report.Snapshot, &expected) || report.Limits != workloadPostgresDiagnosticLimits {
		t.Fatal("diagnostic projection lost exact identity, authority, pending binding, claim generation, or backend facts")
	}
	for _, secret := range secrets {
		if strings.Contains(encoded, secret) {
			t.Fatal("diagnostic projection included an unselected payload")
		}
	}
	if len(encoded) > workloadPostgresDiagnosticBytes {
		t.Fatal("diagnostic projection exceeded its log bound")
	}

	// neither sentinel rows nor malformed text can grow the bounded projection.
	expected.Pairs = append(expected.Pairs, expected.Pairs[0])
	expected.Pairs[0].LegClaims = slices.Repeat(expected.Pairs[0].LegClaims, workloadPostgresDiagnosticClaims)
	expected.Pairs[0].RebindOperationID = secrets[1]
	expected.Pairs[0].PendingBinding.OperationID = secrets[0]
	expected.Pairs[0].RebindStatus = secrets[3]
	expected.Backend.State, expected.Backend.WaitEvent, expected.Backend.BackendXID = secrets[2], secrets[2], secrets[3]
	raw, err = json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	encoded = formatWorkloadPostgresDiagnostic(scope, raw, nil)
	if err := json.Unmarshal([]byte(encoded), &report); err != nil {
		t.Fatal(err)
	}
	if report.ReadStatus != "ok" || !report.Snapshot.PairsOmitted || len(report.Snapshot.Pairs) != workloadPostgresDiagnosticPairs ||
		!report.Snapshot.Pairs[0].ClaimsOmitted || len(report.Snapshot.Pairs[0].LegClaims) != workloadPostgresDiagnosticClaims || len(encoded) > workloadPostgresDiagnosticBytes {
		t.Fatal("diagnostic rows or log bytes exceeded their bounds")
	}
	for _, secret := range secrets {
		if strings.Contains(encoded, secret) {
			t.Fatal("malformed diagnostic text exposed a payload")
		}
	}
}

func TestWorkloadPostgresDiagnosticReadFailuresDoNotExposeErrors(t *testing.T) {
	const payload = "postgres://user:password@target/db SELECT private_payload"
	for _, test := range []struct {
		name, raw, status string
		err               error
	}{
		{name: "driver", status: "unavailable", err: errors.New(payload)},
		{name: "timeout", status: "timeout", err: errors.Join(context.DeadlineExceeded, errors.New(payload))},
		{name: "canceled", status: "canceled", err: errors.Join(context.Canceled, errors.New(payload))},
		{name: "invalid", raw: payload, status: "invalid"},
		{name: "null", raw: "null", status: "invalid"},
		{name: "oversized", raw: strings.Repeat(payload, workloadPostgresDiagnosticBytes), status: "oversized"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := workloadPostgresDiagnosticScope{Service: payload, ServiceID: payload, ServiceRunID: payload, WorkloadSessionID: payload, PairID: payload}
			encoded := formatWorkloadPostgresDiagnostic(scope, []byte(test.raw), test.err)
			var report workloadPostgresDiagnosticReport
			if err := json.Unmarshal([]byte(encoded), &report); err != nil {
				t.Fatal(err)
			}
			if report.ReadStatus != test.status || report.Snapshot != nil || strings.Contains(encoded, payload) || len(encoded) > workloadPostgresDiagnosticBytes {
				t.Fatal("best-effort diagnostic failure changed classification, exposed an error, or exceeded its log bound")
			}
		})
	}
}

type workloadPostgresDiagnosticTestControl struct {
	connectorstream.Control
	pair controlv1.ConnectorPeerPair
	err  error
}

func (c *workloadPostgresDiagnosticTestControl) PrepareConnectorPeerPair(context.Context, string, controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	return c.pair, c.err
}

func TestWorkloadPostgresDiagnosticCapturesOnlyPreparedPairIdentity(t *testing.T) {
	control := &workloadPostgresDiagnosticTestControl{pair: controlv1.ConnectorPeerPair{PairId: "cpp_" + strings.Repeat("a", 22),
		ServiceRunId: "srun_" + strings.Repeat("b", 22), RunNumber: 7, Key: "private-key", SessionKey: "private-session-key"}}
	source := &workloadPostgresDiagnosticSource{}
	wrapper := workloadPostgresDiagnosticControl{Control: control, source: source}
	pair, err := wrapper.PrepareConnectorPeerPair(t.Context(), "db", controlv1.ConnectorPeerPairRequest{})
	if err != nil || !reflect.DeepEqual(pair, control.pair) {
		t.Fatal("diagnostic observation changed the successful control response")
	}
	observed := source.pair.Load()
	if observed == nil || *observed != (workloadPostgresPairIdentity{id: pair.PairId, runID: pair.ServiceRunId, runNumber: uint64(pair.RunNumber)}) {
		t.Fatal("diagnostic observation did not retain the actual prepared pair/run")
	}
	control.pair.PairId, control.err = "uncommitted-pair", context.DeadlineExceeded
	_, err = wrapper.PrepareConnectorPeerPair(t.Context(), "db", controlv1.ConnectorPeerPairRequest{})
	if err != control.err || source.pair.Load() != observed {
		t.Fatal("failed preparation changed the retained diagnostic identity or original error")
	}
}

func TestIntegrationWorkloadPostgresDiagnosticQuery(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "workload-diagnostics")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal("migrate diagnostic fixture")
	}
	inspect, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal("open diagnostic fixture")
	}
	t.Cleanup(func() { _ = inspect.Close() })
	target, err := inspect.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal("begin retained backend transaction")
	}
	defer target.Rollback()
	var scope workloadPostgresDiagnosticScope
	var xid string
	if err := target.QueryRowContext(t.Context(), "SELECT pg_backend_pid(), pg_current_xact_id()::text /* private-target-SQL-payload */").Scan(&scope.BackendPID, &xid); err != nil {
		t.Fatal("observe retained backend identity")
	}
	// no saved pair is needed to parse the complete diagnostic statement. this
	// separate inspection query must still find the exact existing backend,
	// preserve missing authority as null, and omit its SQL text and credentials.
	ctx, cancel := context.WithTimeout(context.Background(), workloadPostgresDiagnosticTimeout)
	defer cancel()
	var raw []byte
	err = inspect.QueryRowContext(ctx, workloadPostgresDiagnosticQuery, "absent", "absent", "absent", 1, scope.BackendPID, "absent").Scan(&raw)
	encoded := formatWorkloadPostgresDiagnostic(scope, raw, err)
	var report workloadPostgresDiagnosticReport
	if err := json.Unmarshal([]byte(encoded), &report); err != nil {
		t.Fatal(err)
	}
	if report.ReadStatus != "ok" || report.Snapshot == nil || report.Snapshot.Backend == nil || report.Snapshot.WorkloadAuthority != nil || len(report.Snapshot.Pairs) != 0 {
		t.Fatal("diagnostic query did not observe the exact live backend and missing saved authority")
	}
	if report.Snapshot.Backend.BackendXID != xid || report.Snapshot.Backend.TransactionStartedAt == nil || strings.Contains(encoded, "private-target-SQL-payload") || len(encoded) > workloadPostgresDiagnosticBytes {
		t.Fatal("backend transaction facts were lost, query text escaped, or log bound was exceeded")
	}
}
