package controlstate

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestIntegrationConnectionAccountingIncludesDedicatedLifetimes(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "connection_accounting")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	tlsStarted, dnsStarted := make(chan struct{}), make(chan struct{})
	tlsDone, dnsDone := make(chan error, 1), make(chan error, 1)
	releaseDNS := make(chan struct{})
	leaderCtx, stopLeader := context.WithCancel(ctx)
	defer stopLeader()
	workers.Go(func() {
		tlsDone <- database.RunControlTLSLeader(leaderCtx, func(ctx context.Context) error {
			close(tlsStarted)
			<-ctx.Done()
			return nil
		})
	})
	workers.Go(func() {
		dnsDone <- database.WithDNSChallengeLock(ctx, "_acme-challenge.accounting.example.test", func() error {
			close(dnsStarted)
			select {
			case <-releaseDNS:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
	awaitIntegrationResult(t, ctx, tlsStarted)
	awaitIntegrationResult(t, ctx, dnsStarted)
	snapshot, err := database.Diagnostics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"tls_leadership", "dns_challenge"} {
		if counts := snapshot.Connections[purpose]; counts.Open != 1 || counts.Opened != 1 || counts.Closed != 0 || counts.Connecting != 0 {
			t.Fatalf("live %s counts = %+v", purpose, counts)
		}
	}
	if counts := snapshot.Connections["request_pool"]; counts.Open < 1 || counts.Opened < 1 {
		t.Fatalf("request connections missing: %+v", counts)
	}
	if len(snapshot.ActiveOperations) != 0 {
		t.Fatalf("dedicated operations leaked into request activity: %+v", snapshot.ActiveOperations)
	}
	// this disposable PostgreSQL server has no PgBouncer admin database.
	if snapshot.Pooler == nil || snapshot.Pooler.Error == "" || snapshot.Pooler.Clients != nil || snapshot.Pooler.Settings != nil {
		t.Fatalf("missing pooler reported inferred values: %+v", snapshot.Pooler)
	}
	stopLeader()
	close(releaseDNS)
	if err := awaitIntegrationResult(t, ctx, tlsDone); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, dnsDone); err != nil {
		t.Fatal(err)
	}
	counts := database.connections.snapshot()
	for _, purpose := range []string{"tls_leadership", "dns_challenge", "diagnostics"} {
		if got := counts[purpose]; got.Open != 0 || got.Opened != 1 || got.Closed != 1 || got.Connecting != 0 {
			t.Fatalf("closed %s counts = %+v", purpose, got)
		}
	}
	if got := counts["pooler_diagnostics"]; got.Failed != 1 || got.Open != 0 || got.Connecting != 0 {
		t.Fatalf("failed admin connect counts = %+v", got)
	}
	database.Close()
	if got := database.connections.snapshot()["request_pool"]; got.Open != 0 || got.Opened != got.Closed {
		t.Fatalf("pool shutdown did not balance counts: %+v", got)
	}
}

func TestIntegrationConnectionAccountingTracksServerDisconnect(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "connection_disconnect")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, database.dedicatedConnectionConfig(dnsChallengeConnection))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	if _, err := database.pool.Exec(ctx, "SELECT pg_terminate_backend($1)", connection.PgConn().PID()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, "SELECT 1"); err == nil {
		t.Fatal("terminated connection remained usable")
	}
	select {
	case <-connection.PgConn().CleanupDone():
	case <-ctx.Done():
		t.Fatal("terminated connection did not clean up")
	}
	if got := database.connections.snapshot()["dns_challenge"]; got.Open != 0 || got.Opened != 1 || got.Closed != 1 {
		t.Fatalf("server-disconnected counts = %+v", got)
	}
}
