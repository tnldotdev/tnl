package state

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationVisitorIssuanceRetentionPreservesAuthoritySnapshot(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_retention_snapshot")
	ctx, scope := visitorSigningConcurrencySource(t, d, now)
	initial, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	keyRevision, err := q.ReadVisitorVerificationKeyRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	authority, err := d.visitorAuthorityForSource(ctx, tx, scope, BrowserTokenSource{}, newAuthorizationClock(now))
	if err != nil {
		t.Fatal(err)
	}
	// another signer extends retention without changing the key, policy,
	// source authority, or this permission's fixed deadline.
	longer := initial.Permission
	longer.ExpiresAt = longer.ExpiresAt.Add(time.Minute)
	if _, err := signStateTestPermission(ctx, d, testVisitorIssuer, longer, now); err != nil {
		t.Fatal(err)
	}
	if current, err := q.ReadVisitorVerificationKeyRevision(ctx); err != nil || current != keyRevision {
		t.Fatal("retention changed verification authority", current, keyRevision, err)
	}
	token, err := d.signVisitorPermission(ctx, tx, testVisitorIssuer, authority.Permission, now)
	if err != nil {
		t.Fatal("retention-only update invalidated the current permission snapshot", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	verified, err := visitortoken.VerifyBearer(token, stateTestVisitorView(authority.Permission, stateTestVisitorKeys(t, d, now), now), now)
	if err != nil || !verified.Facts().ExpiresAt.Equal(authority.Permission.ExpiresAt) || verified.Facts().Subject != authority.Permission.Subject {
		t.Fatal("retention changed the issued subject or fixed deadline", err)
	}
}

func TestIntegrationVisitorIssuanceNecessaryRetentionExtensionIsDurable(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_retention_extension")
	ctx, scope := visitorSigningConcurrencySource(t, d, now)
	initial, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Second)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	authority, err := d.visitorAuthorityForSource(ctx, tx, scope, BrowserTokenSource{}, newAuthorizationClock(at))
	if err != nil {
		t.Fatal(err)
	}
	shorter := initial.Permission
	shorter.ExpiresAt = shorter.ExpiresAt.Add(time.Second)
	if !authority.Permission.ExpiresAt.After(shorter.ExpiresAt) {
		t.Fatal("fixture does not require a retention extension")
	}
	if _, err := signStateTestPermission(ctx, d, testVisitorIssuer, shorter, now); err != nil {
		t.Fatal(err)
	}
	_, err = d.signVisitorPermission(ctx, tx, testVisitorIssuer, authority.Permission, at)
	var conflict *pgconn.PgError
	if !errors.As(err, &conflict) || conflict.Code != "40001" {
		t.Fatal("necessary retention write ignored its stale snapshot", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var retained time.Time
	if err := d.pool.QueryRow(ctx, `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&retained); err != nil || !retained.Equal(shorter.ExpiresAt) {
		t.Fatal("failed retention extension did not roll back", retained, err)
	}
	fresh, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, at)
	if err != nil || !fresh.Permission.ExpiresAt.Equal(authority.Permission.ExpiresAt) {
		t.Fatal("fresh decision lost the fixed permission deadline", err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&retained); err != nil || !retained.Equal(fresh.Permission.ExpiresAt) {
		t.Fatal("necessary retention extension was not durable", retained, err)
	}
}
