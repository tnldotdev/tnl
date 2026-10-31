package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationVisitorSigningNoOpPreservesSnapshot(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_signing_noop")
	permission := signingTestPermission(now)
	if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now); err != nil {
		t.Fatal(err)
	}
	versions := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(t.Context(), `SELECT i.xmin::text || ':' || k.xmin::text FROM control.visitor_token_issuer i CROSS JOIN control.visitor_token_keys k`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := versions()
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	var snapshot string
	if err := tx.QueryRow(t.Context(), `SELECT pg_current_snapshot()::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	shorter := permission
	shorter.ExpiresAt = permission.ExpiresAt.Add(-time.Minute)
	for _, p := range []visitortoken.Permission{permission, shorter} {
		if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, p, now); err != nil {
			t.Fatal(err)
		}
	}
	// exercise the SQL guard independently of the locked-row fast path.
	row, err := controlstatedb.New(tx).LockVisitorTokenSigningKey(t.Context())
	if err != nil {
		t.Fatal("no-op signing invalidated a repeatable-read snapshot", err)
	}
	for _, until := range []time.Time{permission.ExpiresAt, shorter.ExpiresAt} {
		changed, err := controlstatedb.New(tx).RetainVisitorTokenSigningKey(t.Context(), controlstatedb.RetainVisitorTokenSigningKeyParams{ID: row.ID, ExpiresAt: timestamptz(until)})
		if err != nil || changed != 0 {
			t.Fatal("sufficient retention wrote a row version", changed, err)
		}
	}
	if _, err := d.signVisitorPermission(t.Context(), tx, testVisitorIssuer, permission, now); err != nil {
		t.Fatal("unchanged issuer invalidated a repeatable-read snapshot", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after := versions(); before != after {
		t.Fatalf("no-op issuer/key retention changed tuple versions: %s -> %s", before, after)
	}
	longer := permission
	longer.ExpiresAt = permission.ExpiresAt.Add(time.Minute)
	if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, longer, now); err != nil {
		t.Fatal(err)
	}
	var retained time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE id=$1`, row.ID).Scan(&retained); err != nil || !retained.Equal(longer.ExpiresAt) || versions() == before {
		t.Fatal("necessary retention extension was not durable", retained, err)
	}
}

func visitorSigningConcurrencySource(t *testing.T, d *Database, now time.Time) (context.Context, visitorscope.Scope) {
	t.Helper()
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	return WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}), visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
}

func TestIntegrationVisitorSigningBootstrapWait(t *testing.T) {
	for _, mode := range []string{"prepare", "repeatable-read-issue"} {
		t.Run(mode, func(t *testing.T) {
			d, url, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_bootstrap")
			other, err := Open(t.Context(), url, testStorageKey, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(other.Close)
			source, scope := visitorSigningConcurrencySource(t, d, now)
			ctx, cancel := context.WithTimeout(source, 10*time.Second)
			defer cancel()
			first, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, first)
			if _, err := d.signVisitorPermission(ctx, first, testVisitorIssuer, signingTestPermission(now), now); err != nil {
				t.Fatal(err)
			}
			done, join := nativePairWorker(t, ctx, func(ctx context.Context) error {
				if mode == "prepare" {
					return other.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now)
				}
				_, err := other.issueVisitorTokenTransaction(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
				return err
			})
			defer join()
			waitForPostgresBlock(t, ctx, d, int32(first.Conn().PgConn().PID()), done)
			if err := first.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			if mode == "prepare" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var serialization *pgconn.PgError
				if !errors.As(err, &serialization) || serialization.Code != "40001" {
					t.Fatal("bootstrap issued from a snapshot missing the committed issuer", err)
				}
			}
			issued, err := other.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
			if err != nil || issued.Token == "" || len(stateTestVisitorKeys(t, d, now)) != 1 {
				t.Fatal("bootstrap did not converge on one issuer/key", err)
			}
			if err := other.PrepareVisitorSigningKeys(ctx, "https://other.example.test", now); !errors.Is(err, ErrVisitorSigningKey) {
				t.Fatal("bootstrap changed the durable issuer", err)
			}
		})
	}
}

func TestIntegrationVisitorSigningRotationWait(t *testing.T) {
	for _, emergency := range []bool{false, true} {
		for _, order := range []string{"issue-first", "rotate-first"} {
			name := "ordinary/" + order
			if emergency {
				name = "emergency/" + order
			}
			t.Run(name, func(t *testing.T) {
				d, url, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_rotation_wait")
				other, err := Open(t.Context(), url, testStorageKey, "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(other.Close)
				source, scope := visitorSigningConcurrencySource(t, d, now)
				ctx, cancel := context.WithTimeout(source, 10*time.Second)
				defer cancel()
				original, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
				if err != nil {
					t.Fatal(err)
				}
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if order == "issue-first" {
					// issuance retains the issuer lock until its permission commits.
					original, err = d.issueVisitorToken(ctx, gate, testVisitorIssuer, scope, BrowserTokenSource{}, now)
					if err != nil {
						t.Fatal(err)
					}
				} else if _, err := controlstatedb.New(gate).LockVisitorTokenSigningKey(ctx); err != nil {
					t.Fatal(err)
				}
				rotated, joinRotation := nativePairWorker(t, ctx, func(ctx context.Context) error {
					return other.RotateVisitorSigningKey(ctx, testVisitorIssuer, emergency, now)
				})
				defer joinRotation()
				rotationPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), rotated)
				var stale <-chan error
				if order == "rotate-first" {
					// rotation holds the issuer while waiting on the key. this reader
					// authorizes against the pre-rotation repeatable-read snapshot.
					tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
					if err != nil {
						t.Fatal(err)
					}
					defer rollbackTestTransaction(t, tx)
					done, joinIssue := nativePairWorker(t, ctx, func(ctx context.Context) error {
						_, err := d.issueVisitorToken(ctx, tx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
						return err
					})
					defer joinIssue()
					waitForPostgresBlock(t, ctx, d, rotationPID, done)
					stale = done
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, rotated); err != nil {
					t.Fatal(err)
				}
				if stale != nil {
					err := awaitIntegrationResult(t, ctx, stale)
					var serialization *pgconn.PgError
					if !errors.As(err, &serialization) || serialization.Code != "40001" {
						t.Fatal("stale snapshot signed after rotation", err)
					}
				}
				keys := stateTestVisitorKeys(t, d, now)
				_, err = visitortoken.VerifyBearer(original.Token, stateTestVisitorView(original.Permission, keys, now), now)
				if emergency && !errors.Is(err, visitortoken.ErrKey) || !emergency && err != nil {
					t.Fatal("rotation lost its verification boundary", err)
				}
				issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := visitortoken.VerifyBearer(issued.Token, stateTestVisitorView(issued.Permission, keys, now), now); err != nil {
					t.Fatal("fresh transaction did not use the rotated key", err)
				}
			})
		}
	}
}
