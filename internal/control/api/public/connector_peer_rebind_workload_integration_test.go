package public

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/identity/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func exerciseUncappedWorkloadConnectorRebind(t *testing.T, job *workload.Client, service, databaseURL string) {
	t.Helper()
	ctx := t.Context()
	session, err := job.Session()
	if err != nil || session.ExpiresAt != nil {
		t.Fatal("expected an uncapped workload session", err)
	}
	selected, err := job.SelectServiceRun(ctx, service)
	if err != nil || selected.PairReady == nil {
		t.Fatal("workload selection missing ready pair", err)
	}
	owner, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	create := controlv1.ConnectorPeerPairRequest{ServiceRunId: selected.ServiceRunId, RunNumber: selected.RunNumber, PublisherIdentityId: selected.PairReady.PublisherIdentityId,
		Subject: session.Subject, Action: "create", IdempotencyKey: owner, RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ExpectedRelays: selected.PairReady.Relays}
	message, err := controlv1.ConnectorPeerPairProofMessage(service, create)
	if err != nil {
		t.Fatal(err)
	}
	create.Signature = base64.RawURLEncoding.EncodeToString(job.Sign(message))
	pair, err := job.PrepareConnectorPeerPair(ctx, service, create)
	if err != nil {
		t.Fatal("uncapped pair creation", err)
	}
	operation, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	prepare := controlv1.ConnectorPeerPairRebindRequest{Phase: controlv1.ConnectorPeerPairPrepare, ExpectedGeneration: pair.DeliveryGeneration, ExpectedRelays: pair.Relays,
		IdempotencyKey: owner, OperationId: operation, ServiceRunId: pair.ServiceRunId, RunNumber: pair.RunNumber, PublisherIdentityId: pair.PublisherIdentityId,
		TrustRevision: pair.TrustRevision, Subject: pair.Subject, RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
	proof, err := controlv1.ConnectorPeerPairRebindProof(service, pair.PairId, prepare)
	if err != nil {
		t.Fatal(err)
	}
	message, err = proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	prepare.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	var problem *clientcontrol.ProblemError
	if _, err := job.RebindConnectorPeerPair(ctx, service, pair.PairId, prepare); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("uncapped rebind bypassed its signed proof", err)
	}
	prepare.Signature = base64.RawURLEncoding.EncodeToString(job.Sign(message))
	state, err := job.RebindConnectorPeerPair(ctx, service, pair.PairId, prepare)
	if err != nil || state.Active == nil || state.Pending == nil || state.PendingUntil == nil {
		t.Fatal("uncapped rebind preparation", err)
	}
	if state.Active.PairId != pair.PairId || state.Pending.PairId != pair.PairId || state.Pending.SessionKey != pair.SessionKey || state.Pending.DeliveryGeneration != pair.DeliveryGeneration+1 ||
		state.Pending.ExpiresAt.After(*state.PendingUntil) || state.PendingUntil.After(session.LeaseExpiresAt) || state.PendingUntil.After(session.IdentityExpiresAt) {
		t.Fatal("uncapped rebind changed its owner or escaped current authority")
	}
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `UPDATE control.workload_sessions SET lease_expires_at=clock_timestamp() WHERE id=$1`, session.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := job.RebindConnectorPeerPair(ctx, service, pair.PairId, prepare); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("uncapped rebind retry borrowed an expired server lease", err)
	}
}
