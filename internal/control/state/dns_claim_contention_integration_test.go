package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationDNSClaimLocksDoNotBlockSiblingNames(t *testing.T) {
	d, now, _, team := newAuthorityTeam(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `INSERT INTO control.domains(id,kind,team_id,canonical_domain,state,authority_revision,created_at,updated_at)
	    VALUES('held-domain','custom',$1,'held.example.com','pending',1,$2,$2)`, team.ID, now); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() { done <- d.ReserveOperatorNameservers(ctx, "held.example.com", "NHELD") })
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if err := d.ReserveOperatorNameservers(progress, "other.example.com", "NOTHER"); err != nil {
		t.Fatal("a domain claim blocked unrelated nameserver reservations", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("nameserver reservation did not recheck the committed parent claim", err)
	}
	var saved bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.operator_nameserver_hostnames WHERE delegation_set_id='NHELD')`).Scan(&saved); err != nil || saved {
		t.Fatal("conflicting reservation left saved nameservers", err)
	}
}
