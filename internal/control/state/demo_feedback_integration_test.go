package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDemoFeedbackCleanupAndRetainedProjectFeedback(t *testing.T) {
	for _, crashed := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "expiry"}[crashed], func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			d, ctx, now := f.database, t.Context(), f.now
			f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
			if _, err := d.pool.Exec(ctx, "UPDATE control.services SET ephemeral=true,expires_at=$2 WHERE id=$1", f.service.ID, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			f.run = f.publish(t, f.service)
			demo, err := d.CreateServiceRunPreview(ctx, f.auth(), now)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := d.CreateServiceRunPreview(ctx, f.auth(), now)
			if err != nil || retry.ID != demo.ID {
				t.Fatal("demo preview retry", retry, err)
			}
			project := f.preview(t, "real-project", f.service)
			actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", BrowserCookieSecret: feedbackBrowserSecret(t, ctx, f, demo.ID, f.project.ActorID)}
			for _, preview := range []Preview{demo, project} {
				if _, err := d.AuthorizeReviewerFeedback(ctx, f.auth(), preview.ID, "report", actor, now); err != nil {
					t.Fatal(err)
				}
			}
			session := browserTestControlSession(t, d, f.project.ActorID, now)
			owner := WithControlPrincipal(ctx, ControlPrincipal{IdentityID: f.project.ActorID, SessionID: session.SessionID})
			if crashed {
				if _, err := d.ExpireServiceRuns(ctx, now.Add(10*time.Minute)); err != nil {
					t.Fatal(err)
				}
			} else if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := d.ExpireServiceRuns(ctx, now.Add(10*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := d.GetPreview(ctx, demo.ID); !errors.Is(err, ErrPreviewNotFound) {
				t.Fatal("demo preview survived", err)
			}
			if _, err := d.AuthorizeReviewerFeedback(ctx, f.auth(), demo.ID, "read", actor, now.Add(10*time.Minute)); err == nil {
				t.Fatal("closed demo retained authorization")
			}
			service, err := controlstatedb.New(d.pool).GetFeedbackService(ctx, f.service.ID)
			if err != nil || service.TeamID != text(f.project.TeamID) || service.GuestID.Valid || !service.DeletedAt.Valid {
				t.Fatal("lost retained feedback ownership", service, err)
			}
			if _, err := d.AuthorizeImplementerFeedback(owner, f.project.ActorID, f.service.ID, project.ID, "thread.resolved", now.Add(10*time.Minute)); err != nil {
				t.Fatal("retained project feedback could not be resolved", err)
			}
			reply, err := d.AuthorizeImplementerFeedback(owner, f.project.ActorID, f.service.ID, project.ID, "reply", now.Add(10*time.Minute))
			if err != nil || !reply.Author.Verified || reply.Author.IdentityId == nil || *reply.Author.IdentityId != f.project.ActorID {
				t.Fatal("authorized manager could not reply to retained resolved feedback", err)
			}
			if _, err := d.AuthorizeReviewerFeedback(ctx, f.auth(), project.ID, "reply", actor, now.Add(10*time.Minute)); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("retained history restored deleted service reviewer authority", err)
			}
		})
	}
}
