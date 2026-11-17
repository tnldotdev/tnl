package state

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegrationDNSRecordLockUsesFullNormalizedName(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "dns_record_names")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()

	challengeCtx, stopChallenge := context.WithCancel(ctx)
	defer stopChallenge()
	challengeEntered, challengeDone := make(chan struct{}), make(chan error, 1)
	workers.Go(func() {
		challengeDone <- database.WithDNSRecordLock(challengeCtx, "_acme-challenge.Api.Example.Test.", func() error {
			close(challengeEntered)
			<-challengeCtx.Done()
			return challengeCtx.Err()
		})
	})
	awaitIntegrationResult(t, ctx, challengeEntered)
	holderPID := func(excluded int32) int32 {
		t.Helper()
		var pid int32
		if err := database.pool.QueryRow(ctx, `SELECT pid FROM pg_locks
		    WHERE locktype='advisory' AND granted AND pid<>$1
		      AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`, excluded).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		return pid
	}
	challengePID := holderPID(0)

	waiterCtx, stopWaiter := context.WithCancel(ctx)
	defer stopWaiter()
	challengeWaiterDone := make(chan error, 1)
	var challengeWaiterCalls atomic.Int32
	workers.Go(func() {
		challengeWaiterDone <- database.WithDNSRecordLock(waiterCtx, "_ACME-CHALLENGE.api.example.test", func() error {
			challengeWaiterCalls.Add(1)
			return nil
		})
	})
	waitForPostgresBlock(t, ctx, database, challengePID, challengeWaiterDone)
	if challengeWaiterCalls.Load() != 0 {
		t.Fatal("equivalent challenge name bypassed its held lock")
	}

	// address publication must finish while challenge cleanup is still held.
	if err := database.WithDNSRecordLock(ctx, "API.EXAMPLE.TEST.", func() error {
		return database.Health(ctx)
	}); err != nil {
		t.Fatalf("address record waited for its separate challenge record: %v", err)
	}
	select {
	case err := <-challengeDone:
		t.Fatalf("challenge lock ended before address publication completed: %v", err)
	default:
	}
	stopWaiter()
	if err := awaitIntegrationResult(t, ctx, challengeWaiterDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceling a blocked challenge lock: %v", err)
	}
	if challengeWaiterCalls.Load() != 0 {
		t.Fatal("canceled challenge waiter entered its callback")
	}

	addressEntered, releaseAddress := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseAddress) })
	defer release()
	addressDone, addressWaiterDone := make(chan error, 1), make(chan error, 1)
	var addressCalls atomic.Int32
	workers.Go(func() {
		addressDone <- database.WithDNSRecordLock(ctx, "Api.Example.Test.", func() error {
			addressCalls.Add(1)
			close(addressEntered)
			select {
			case <-releaseAddress:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
	awaitIntegrationResult(t, ctx, addressEntered)
	addressPID := holderPID(challengePID)
	workers.Go(func() {
		addressWaiterDone <- database.WithDNSRecordLock(ctx, "api.example.test", func() error {
			addressCalls.Add(1)
			return database.Health(ctx)
		})
	})
	waitForPostgresBlock(t, ctx, database, addressPID, addressWaiterDone)
	if addressCalls.Load() != 1 {
		t.Fatal("equivalent address name bypassed its held lock")
	}
	release()
	for _, done := range []chan error{addressDone, addressWaiterDone} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	if addressCalls.Load() != 2 {
		t.Fatal("address waiter did not resume after its holder released")
	}

	stopChallenge()
	if err := awaitIntegrationResult(t, ctx, challengeDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceling the challenge lock holder: %v", err)
	}
	if err := database.WithDNSRecordLock(ctx, "_acme-challenge.api.example.test", func() error {
		return database.Health(ctx)
	}); err != nil {
		t.Fatalf("challenge lock was not released after cancellation: %v", err)
	}
	var remaining int
	if err := database.pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks
	    WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining DNS record locks=%d: %v", remaining, err)
	}
	connections := database.connections.snapshot()["dns_challenge"]
	if connections.Open != 0 || connections.Connecting != 0 || connections.Opened != connections.Closed {
		t.Fatalf("DNS record lock connections did not join cleanup: %+v", connections)
	}
}
