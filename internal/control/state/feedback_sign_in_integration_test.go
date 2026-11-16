package state

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationFeedbackPolicyCannotEnableAnonymousAuthors(t *testing.T) {
	f := newServiceHTTPFixture(t)
	ctx := t.Context()
	policy, err := f.database.GetTeamFeedbackPolicy(ctx, f.project.ActorID, f.project.TeamID)
	if err != nil || policy.Authors != "signed_in" {
		t.Fatal("new team did not require signed-in feedback authors", policy, err)
	}
	for _, unsupported := range []string{"anyone", "", "anonymous"} {
		if _, err := f.database.SetTeamFeedbackPolicy(ctx, f.project.ActorID, f.project.TeamID, unsupported, f.now); !errors.Is(err, ErrAuthorityInvalid) {
			t.Fatal("unsupported feedback author policy was accepted", unsupported, err)
		}
	}
	if _, err := f.database.pool.Exec(ctx, `UPDATE control.teams SET feedback_authors='anyone' WHERE id=$1`, f.project.TeamID); err == nil {
		t.Fatal("stored policy accepted anonymous feedback authors")
	}
	for _, authors := range []string{"team_members", "signed_in"} {
		if _, err := f.database.SetTeamFeedbackPolicy(ctx, f.project.ActorID, f.project.TeamID, authors, f.now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationFeedbackSignInLeavesHistoricalAuthorsUnchanged(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "historical-feedback", f.service)
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9",
		BrowserCookieSecret: feedbackBrowserSecret(t, t.Context(), f, preview.ID, f.project.ActorID)}
	thread, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "historical"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	// seed a historical unverified report without enabling anonymous writes.
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.feedback_threads
		SET author_identity_id=NULL, author_display_name='Old reviewer', author_verified=false WHERE id=$1`, thread.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.feedback_events
		SET author_identity_id=NULL, author_display_name=NULL, author_verified=false WHERE feedback_id=$1`, thread.ID); err != nil {
		t.Fatal(err)
	}
	before, err := f.database.GetFeedback(t.Context(), thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	history, err := f.database.ListFeedbackEventsForThread(t.Context(), thread.ID, 0)
	if err != nil || len(history.Events) != 1 {
		t.Fatal("historical event missing", err)
	}
	if _, err := f.database.SetTeamFeedbackPolicy(t.Context(), f.project.ActorID, f.project.TeamID, "team_members", f.now); err != nil {
		t.Fatal(err)
	}
	event, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "A current signed-in reply", IdempotencyKey: "current-author",
		Actor: FeedbackActor{Kind: "implementer", IdentityID: f.project.ActorID},
	}, f.now)
	if err != nil || !event.AuthorVerified || event.AuthorIdentityID != f.project.ActorID {
		t.Fatal("current event lost its authenticated author", err)
	}
	after, err := f.database.GetFeedback(t.Context(), thread.ID)
	if err != nil || after.AuthorVerified || after.AuthorIdentityID != "" || after.AuthorDisplayName != before.AuthorDisplayName ||
		after.ReportText != before.ReportText || !reflect.DeepEqual(after.SourceAtReport, before.SourceAtReport) {
		t.Fatal("current feedback policy rewrote the historical report", err)
	}
	events, err := f.database.ListFeedbackEventsForThread(t.Context(), thread.ID, 0)
	if err != nil || len(events.Events) != 2 || !reflect.DeepEqual(events.Events[0], history.Events[0]) {
		t.Fatal("current feedback policy rewrote historical authorship", err)
	}
}
