package state

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationBrowserAndFeedbackReaderLocks(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d := f.database
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "readers", f.service)
	cookie := feedbackBrowserSecret(t, t.Context(), f, preview.ID, f.project.ActorID)
	session := browserTestControlSession(t, d, f.project.ActorID, f.now)
	auth := f.auth()
	held, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, held)
	if err := lockServiceForRun(t.Context(), held, f.service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(t.Context(), `SELECT id FROM control.service_runs WHERE id=$1 FOR SHARE`, auth.RunID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		read func(context.Context) error
	}{
		{"session", func(ctx context.Context) error {
			_, err := d.ServiceBrowserSession(ctx, auth, base64.RawURLEncoding.EncodeToString(cookie), false, f.now)
			return err
		}},
		{"reviewer", func(ctx context.Context) error {
			_, err := d.AuthorizeReviewerFeedback(ctx, auth, preview.ID, "read", FeedbackActor{
				Kind: "reviewer", SourceIP: "192.0.2.9", BrowserCookieSecret: cookie,
			}, f.now)
			return err
		}},
		{"implementer", func(ctx context.Context) error {
			ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: f.project.ActorID, SessionID: session.SessionID})
			_, err := d.AuthorizeImplementerFeedback(ctx, f.project.ActorID, f.service.ID, preview.ID, "read", f.now)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := test.read(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	sessionOp := func(revoke bool) chan error {
		done := make(chan error, 1)
		workers.Go(func() {
			_, err := d.ServiceBrowserSession(ctx, auth, base64.RawURLEncoding.EncodeToString(cookie), revoke, f.now)
			done <- err
		})
		return done
	}
	logout := sessionOp(true)
	writer := waitForPostgresBlock(t, ctx, d, int32(held.Conn().PgConn().PID()), logout)
	check := sessionOp(false)
	waitForPostgresBlock(t, ctx, d, writer, check)
	if err := held.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, logout); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, check); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("late browser session read bypassed logout", err)
	}
}

func TestIntegrationManagementReadersShareAuthority(t *testing.T) {
	f := newServiceManagementFixture(t)
	held, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, held)
	if _, err := held.Exec(t.Context(), `SELECT pg_advisory_xact_lock_shared(837174137711267953)`); err != nil {
		t.Fatal(err)
	}
	if err := lockServiceForRun(t.Context(), held, f.local.ID); err != nil {
		t.Fatal(err)
	}
	read := func(ctx context.Context, op string) error {
		switch op {
		case "grants":
			_, _, err := f.d.ListServiceGrants(ctx, f.local.ID, f.member.IdentityID, "")
			return err
		case "http-grants":
			_, err := f.d.ListServiceHTTPGrants(ctx, f.local.ID, f.member.IdentityID, f.now)
			return err
		case "invitations":
			_, _, err := f.d.ListServiceInvitations(ctx, f.local.ID, f.member.IdentityID, "")
			return err
		case "configuration":
			_, _, err := f.d.GetServiceConfiguration(ctx, f.local.ID, f.member.IdentityID)
			return err
		default:
			_, err := f.d.GetService(ctx, f.local.ID, f.member.IdentityID)
			return err
		}
	}
	for _, op := range []string{"grants", "http-grants", "invitations", "service", "configuration"} {
		t.Run(op, func(t *testing.T) {
			proof := managementActorProof(t, f.d, f.member.IdentityID, op, f.now)
			ctx, cancel := context.WithTimeout(WithServiceActorProof(t.Context(), proof, op), 2*time.Second)
			defer cancel()
			if err := read(ctx, op); err != nil {
				t.Fatal(err)
			}
			if err := read(ctx, op); !errors.Is(err, ErrOIDCAssertionReplay) {
				t.Fatal("signed read did not consume the assertion", err)
			}
		})
	}
	if err := held.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	edit, err := f.d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, edit)
	if _, err := controlstatedb.New(edit).LockLocalTeamForMutation(ctx, f.team); err != nil {
		t.Fatal(err)
	}
	proof := managementActorProof(t, f.d, f.member.IdentityID, "revoked", f.now)
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	workers.Go(func() { done <- read(WithServiceActorProof(ctx, proof, proof.Nonce), "grants") })
	waitForPostgresBlock(t, ctx, f.d, int32(edit.Conn().PgConn().PID()), done)
	if _, err := edit.Exec(ctx, `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, f.team, f.member.IdentityID, f.now); err != nil {
		t.Fatal(err)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceManagerRequired) {
		t.Fatal("suspended member read service grants", err)
	}
}
