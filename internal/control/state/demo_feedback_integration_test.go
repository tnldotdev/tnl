package state

import (
	"encoding/json"
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
			if _, err := d.pool.Exec(ctx, "UPDATE control.services SET ephemeral = true, expires_at = $2 WHERE id = $1", f.service.ID, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			f.run = f.publish(t, f.service)
			demo, err := d.CreateServiceRunPreview(ctx, f.auth(), now)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := d.CreateServiceRunPreview(ctx, f.auth(), now)
			if err != nil || demo.ID != retry.ID {
				t.Fatalf("demo preview retry = %+v, %v", retry, err)
			}
			project := f.preview(t, "real-project", f.service)
			create := func(preview Preview, key string) FeedbackThread {
				thread, err := d.CreateFeedback(ctx, f.auth(), CreateFeedbackRequest{PreviewID: preview.ID, Service: "demo", PagePath: "/", ReportText: "A suggestion", Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`), SourceAtReport: feedbackTestSource(t), IdempotencyKey: key, Actor: FeedbackActor{Kind: "reviewer", VisitAllowed: true, SourceIP: "192.0.2.9"}}, now)
				if err != nil {
					t.Fatal(err)
				}
				return thread
			}
			demoThread, projectThread := create(demo, "demo"), create(project, "project")
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
			if _, err := d.GetFeedback(ctx, demoThread.ID); !errors.Is(err, ErrFeedbackNotFound) {
				t.Fatalf("demo comment survived: %v", err)
			}
			if _, err := d.GetPreview(ctx, demo.ID); !errors.Is(err, ErrPreviewNotFound) {
				t.Fatalf("demo preview survived: %v", err)
			}
			if _, err := d.GetFeedback(ctx, projectThread.ID); err != nil {
				t.Fatalf("real feedback removed: %v", err)
			}
			service, err := controlstatedb.New(d.pool).GetFeedbackService(ctx, f.service.ID)
			if err != nil || service.TeamID != text(f.project.TeamID) || service.GuestID.Valid || !service.DeletedAt.Valid {
				t.Fatalf("lost feedback ownership after service expiry: %+v, %v", service, err)
			}
			if _, err := d.AppendFeedback(ctx, AppendFeedbackRequest{FeedbackID: projectThread.ID, Type: FeedbackThreadResolved, IdempotencyKey: "after-stop", Actor: FeedbackActor{Kind: "implementer", IdentityID: f.project.ActorID}}, now.Add(10*time.Minute)); err != nil {
				t.Fatalf("retained feedback could not be resolved: %v", err)
			}
		})
	}
}
