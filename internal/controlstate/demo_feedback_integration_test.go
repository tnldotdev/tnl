package controlstate

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestIntegrationDemoFeedbackCleanupAndRetainedProjectFeedback(t *testing.T) {
	for _, crashed := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "expiry"}[crashed], func(t *testing.T) {
			f := newPublishRunFixture(t)
			d, ctx, now := f.database, t.Context(), f.now
			if _, err := d.pool.Exec(ctx, "UPDATE control.public_urls SET ephemeral = true, expires_at = $2 WHERE id = $1", f.setup.PublicURLID, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			demo, err := d.CreatePublishRunPreview(ctx, f.authentication(), now)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := d.CreatePublishRunPreview(ctx, f.authentication(), now)
			if err != nil || demo.ID != retry.ID {
				t.Fatalf("demo preview retry = %+v, %v", retry, err)
			}
			project, err := d.CreatePreview(ctx, f.request.TeamID, f.request.ActingIdentityID, "real-project", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.AddPreviewPublicURL(ctx, AddPreviewPublicURLRequest{PreviewID: project.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID, IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2}, now); err != nil {
				t.Fatal(err)
			}
			create := func(preview Preview, key string) FeedbackThread {
				thread, err := d.CreateFeedback(ctx, f.authentication(), CreateFeedbackRequest{PreviewID: preview.ID, Service: "demo", PagePath: "/", ReportText: "A suggestion", Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`), SourceAtReport: feedbackTestSource(t), IdempotencyKey: key, Actor: FeedbackActor{Kind: "reviewer", AllowedIP: true}}, now)
				if err != nil {
					t.Fatal(err)
				}
				return thread
			}
			demoThread, projectThread := create(demo, "demo"), create(project, "project")
			if crashed {
				if _, err := d.DeleteExpiredEphemeralPublicURLs(ctx, now.Add(10*time.Minute)); err != nil {
					t.Fatal(err)
				}
			} else if err := d.ClosePublishRun(ctx, f.authentication().PublishRunID, f.authentication().PublishRunToken, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if !crashed {
				if err := d.DeletePublicURL(ctx, f.request.ActingIdentityID, f.setup.PublicURLID, now.Add(2*time.Second)); err != nil {
					t.Fatal(err)
				}
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
			route, err := d.GetPublicURLForFeedbackAuthorization(ctx, f.setup.PublicURLID)
			if err != nil || route.TeamID != f.request.TeamID || route.LifecycleState != PublicURLLifecycleDeleted {
				t.Fatalf("lost feedback ownership after URL expiry: %+v, %v", route, err)
			}
			if _, err := d.AppendFeedback(ctx, AppendFeedbackRequest{FeedbackID: projectThread.ID, Type: FeedbackThreadResolved, IdempotencyKey: "after-stop", Actor: FeedbackActor{Kind: "implementer", IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: route.MutationRevision}}, now.Add(10*time.Minute)); err != nil {
				t.Fatalf("retained feedback could not be resolved: %v", err)
			}
		})
	}
}
