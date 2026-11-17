package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hold the result of the browser lock while another connection changes its
// parent. the refresh decision must use a later snapshot, not the locking join.
type browserRefreshSnapshotTracer struct {
	after func()
}

type browserRefreshLockKey struct{}

func (r *browserRefreshSnapshotTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, browserRefreshLockKey{}, strings.HasPrefix(data.SQL, "-- name: LockServiceHTTPBrowserSession "))
}

func (r *browserRefreshSnapshotTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(browserRefreshLockKey{}) == true && data.Err == nil && r.after != nil {
		after := r.after
		r.after = nil
		after()
	}
}

func testServiceBrowserRefreshSnapshot(t *testing.T, d *Database, service, secret, parent string, now time.Time) {
	for _, revoke := range []bool{false, true} {
		name := "refreshed"
		if revoke {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, parent, now.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET revoked_at=NULL,revoked_by=NULL WHERE id=$1`, parent); err != nil {
					t.Error(err)
				}
			}()
			fresh := now.Add(time.Hour)
			tracer := &browserRefreshSnapshotTracer{after: func() {
				var err error
				if revoke {
					_, err = d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET revoked_at=$2,revoked_by=identity_id WHERE id=$1`, parent, now)
				} else {
					_, err = d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, parent, fresh)
				}
				if err != nil {
					t.Error(err)
				}
			}}
			config := d.pool.Config()
			config.ConnConfig.Tracer = tracer
			pool, err := pgxpool.NewWithConfig(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			reader := &Database{pool: pool, storageKey: d.storageKey}
			called := false
			session, err := reader.RefreshServiceBrowserSession(t.Context(), service, secret, now, func(context.Context, string) (BrowserTokenRotation, error) {
				called = true
				return BrowserTokenRotation{}, errors.New("stale parent triggered rotation")
			})
			if tracer.after != nil || called {
				t.Fatal("refresh used parent state from before the browser lock", err)
			}
			if revoke {
				if !errors.Is(err, ErrPreviewAccess) {
					t.Fatal("parent revocation was missed", err)
				}
			} else if err != nil || !session.AccessExpiresAt.Equal(fresh) {
				t.Fatal("parent refresh was missed", session.AccessExpiresAt, err)
			}
		})
	}
}
