package state

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationFeedbackCombinedBrowserShareUsesVerifiedAuthor(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "combined-feedback", f.service)
	identity := "00000000-0000-4000-8000-000000000002"
	insertAuthorityIdentity(t, d, identity, "", false, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET display_name='Verified reviewer' WHERE id=$1`, identity); err != nil {
		t.Fatal(err)
	}
	handoff, _ := f.browser(t, preview.ID, identity)
	cookie, err := d.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := base64.RawURLEncoding.DecodeString(cookie.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(strings.Repeat("s", 32))
	share := f.share(t, preview.ID, "combined-share", secret, f.service)
	auth := f.auth()
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ServiceRun: &auth, BrowserCookieSecret: browser, ShareID: share.ID, ShareSecret: secret, IdentityID: "forged identity", DisplayName: "forged name", TeamMember: true, VisitAllowed: true}
	thread, err := d.CreateFeedback(t.Context(), auth, CreateFeedbackRequest{PreviewID: preview.ID, Service: "web", PagePath: "/", ReportText: "combined access", AuthorDisplayName: "unverified supplied name", Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`), SourceAtReport: feedbackTestSource(t), IdempotencyKey: "combined-report", Actor: actor}, now)
	if err != nil || thread.AuthorIdentityID != identity || thread.AuthorDisplayName != "Verified reviewer" || !thread.AuthorVerified {
		t.Fatal("combined feedback trusted submitted author facts", thread, err)
	}
	event, err := d.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "follow-up", IdempotencyKey: "combined-reply", Actor: actor}, now)
	if err != nil || event.AuthorIdentityID != identity || event.AuthorDisplayName != "Verified reviewer" || !event.AuthorVerified || event.ActorReference != "identity:"+identity {
		t.Fatal("combined feedback append lost verified author", event, err)
	}
	if _, err := d.RevokeShare(t.Context(), share.ID, f.project.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "revoked", IdempotencyKey: "revoked-combined-reply", Actor: actor}, now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("verified author replaced revoked URL-scoped access", err)
	}
}

func feedbackTestSource(t *testing.T) json.RawMessage {
	t.Helper()
	source, err := json.Marshal(SourceState{
		SchemaVersion: 1,
		HeadCommit:    strings.Repeat("a", 40), ProjectPath: "apps/web", Branch: "perf",
		ChangedFiles: []FeedbackChangedFile{{Path: "Profile.tsx", Status: "modified", BlobID: strings.Repeat("b", 40), Mode: "100644"}},
		Complete:     new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestIntegrationFeedbackReportEventsResolveReopenAndResume(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now := f.database, f.now
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "feedback", f.service)
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share := f.share(t, preview.ID, "feedback-share", secret, f.service)
	redemption, err := database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := base64.RawURLEncoding.Strict().DecodeString(redemption.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	auth := f.auth()
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", ShareID: share.ID, CookieSecret: cookie, ServiceRun: &auth, DisplayName: "forged verified author", TeamMember: true, VisitAllowed: true}
	source := feedbackTestSource(t)
	request := CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/settings/profile", PageTitle: "Profile settings",
		ReportText: "Save says it worked, but changes disappear after reload.", AuthorDisplayName: "Sam",
		Anchor:         json.RawMessage(`{"schema_version":1,"selectors":["[data-testid=save]"],"x":0.5,"y":0.5}`),
		Evidence:       json.RawMessage(`{"schema_version":1,"element":{"role":"button","label":"Save changes","html":"<button onclick='steal()' data-testid='save'>Save</button><script>steal()</script>"},"actions":[{"type":"click","label":"Save changes"}],"failed_requests":[{"method":"POST","path":"/api/profile","status":500,"duration_ms":184}]}`),
		SourceAtReport: source, IdempotencyKey: "first-report", Actor: actor,
	}
	thread, err := database.CreateFeedback(t.Context(), f.auth(), request, now)
	if err != nil || thread.ID == "" || thread.SchemaVersion != 1 || thread.State != FeedbackOpen || !strings.Contains(string(thread.Evidence), "data-testid") ||
		strings.Contains(string(thread.Evidence), "onclick") || strings.Contains(string(thread.Evidence), "<script>") {
		t.Fatalf("submitted report = %+v, %v", thread, err)
	}
	firstPage, err := database.ListFeedbackEventsForTeam(t.Context(), f.project.TeamID, 0)
	if err != nil || len(firstPage.Events) != 1 || firstPage.Events[0].Type != FeedbackCreated || firstPage.Events[0].Cursor == 0 {
		t.Fatalf("initial event = %+v, %v", firstPage, err)
	}
	if thread.AuthorVerified || thread.AuthorIdentityID != "" || firstPage.Events[0].AuthorDisplayName != "" || firstPage.Events[0].AuthorVerified || firstPage.Events[0].ActorReference != share.ID {
		t.Fatal("submitted reviewer assertions reached persistence", thread, firstPage.Events[0])
	}
	retry, err := database.CreateFeedback(t.Context(), f.auth(), request, now.Add(time.Second))
	if err != nil || retry.ID != thread.ID {
		t.Fatalf("retried report = %+v, %v", retry, err)
	}
	altered := request
	altered.ReportText = "different text"
	if _, err := database.CreateFeedback(t.Context(), f.auth(), altered, now); !errors.Is(err, ErrFeedbackIdempotency) {
		t.Fatalf("conflicting report retry = %v", err)
	}
	reply := AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "Still seeing this?", IdempotencyKey: "reply", Actor: actor}
	answered, err := database.AppendFeedback(t.Context(), reply, now.Add(time.Second))
	if err != nil || answered.Cursor <= firstPage.Events[0].Cursor {
		t.Fatalf("reviewer reply = %+v, %v", answered, err)
	}
	duplicate, err := database.AppendFeedback(t.Context(), reply, now.Add(2*time.Second))
	if err != nil || duplicate.Cursor != answered.Cursor {
		t.Fatalf("retried reply = %+v, %v", duplicate, err)
	}
	implementer := FeedbackActor{Kind: "implementer", IdentityID: f.project.ActorID, DisplayName: "forged implementer name"}
	wrongImplementer := AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackUpdate, Text: "Updated the copy", SourceState: source,
		IdempotencyKey: "wrong-owner", Actor: FeedbackActor{Kind: "implementer", IdentityID: "different-identity"},
	}
	if _, err := database.AppendFeedback(t.Context(), wrongImplementer, now.Add(2*time.Second)); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("unrelated implementer changed feedback: %v", err)
	}
	update := AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackUpdate, Text: "Updated the save handler.",
		SourceState: source, IdempotencyKey: "update", Actor: implementer,
	}
	updated, err := database.AppendFeedback(t.Context(), update, now.Add(3*time.Second))
	if err != nil || len(updated.SourceState) == 0 {
		t.Fatalf("source update = %+v, %v", updated, err)
	}
	if updated.AuthorDisplayName == implementer.DisplayName || updated.AuthorIdentityID != implementer.IdentityID || !updated.AuthorVerified || updated.ActorReference != implementer.IdentityID {
		t.Fatal("implementer author was not derived from the transaction", updated)
	}
	resolve := AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackThreadResolved, Text: "Looks good", IdempotencyKey: "reviewer-resolve", Actor: actor}
	if _, err := database.AppendFeedback(t.Context(), resolve, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "late", IdempotencyKey: "late", Actor: actor,
	}, now.Add(5*time.Second)); !errors.Is(err, ErrFeedbackState) {
		t.Fatalf("resolved thread received another reply: %v", err)
	}
	reopen := AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackThreadReopened, Text: "One more suggestion",
		IdempotencyKey: "reopen", Actor: actor,
	}
	reopened, err := database.AppendFeedback(t.Context(), reopen, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err = database.AppendFeedback(t.Context(), reopen, now.Add(6*time.Second))
	if err != nil || duplicate.Cursor != reopened.Cursor {
		t.Fatalf("reopen retry appended another event: %+v, %v", duplicate, err)
	}
	current, err := database.GetFeedback(t.Context(), thread.ID)
	if err != nil || current.State != FeedbackOpen || current.ReportText != thread.ReportText ||
		string(current.SourceAtReport) != string(thread.SourceAtReport) {
		t.Fatalf("original report changed after reopening: %+v, %v", current, err)
	}
	resolved, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackThreadResolved, IdempotencyKey: "resolve", Actor: implementer,
	}, now.Add(6*time.Second))
	if err != nil || resolved.Type != FeedbackThreadResolved {
		t.Fatalf("resolved feedback = %+v, %v", resolved, err)
	}
	if _, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackThreadReopened, IdempotencyKey: "implementer-reopen", Actor: implementer,
	}, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, f.project.ActorID, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "late", IdempotencyKey: "revoked-reviewer", Actor: actor,
	}, now.Add(8*time.Second)); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("revoked reviewer wrote feedback: %v", err)
	}
	events, err := database.ListFeedbackEventsForTeam(t.Context(), f.project.TeamID, firstPage.EventCursor)
	if err != nil || len(events.Events) != 6 || events.EventCursor != events.Events[len(events.Events)-1].Cursor {
		t.Fatalf("resumed events = %+v, %v", events, err)
	}
	for index, event := range events.Events {
		if event.Cursor != firstPage.EventCursor+uint64(index)+1 {
			t.Fatalf("feedback cursor gap at %d: %+v", index, events.Events)
		}
	}
	listed, err := database.ListFeedbackForPage(t.Context(), preview.ID, f.service.ID, "/settings/profile", "")
	if err != nil || len(listed.Threads) != 1 || listed.Threads[0].State != FeedbackOpen {
		t.Fatalf("page feedback = %+v, %v", listed, err)
	}
	if listed.Threads[0].MessageCount != 3 || listed.Threads[0].LatestEventCursor != events.EventCursor || listed.Threads[0].PageTitle != "Profile settings" {
		t.Fatalf("summary activity = %+v", listed.Threads[0])
	}
	all, err := database.ListFeedbackForService(t.Context(), preview.ID, f.service.ID, "", "open", "")
	if err != nil || len(all.Threads) != 1 {
		t.Fatalf("all-page filter = %+v, %v", all, err)
	}
	closed, err := database.ListFeedbackForService(t.Context(), preview.ID, f.service.ID, "", "resolved", "")
	if err != nil || len(closed.Threads) != 0 {
		t.Fatalf("resolved filter = %+v, %v", closed, err)
	}
	other, err := database.ListFeedbackForService(t.Context(), preview.ID, "svc_"+strings.Repeat("Z", 22), "", "", "")
	if err != nil || len(other.Threads) != 0 {
		t.Fatalf("hostname scope leaked feedback: %+v, %v", other, err)
	}
}

func TestIntegrationFeedbackCursorsOrderConcurrentReports(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.service = f.local(t, "web", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "concurrent-reports", f.service)
	started := make(chan struct{})
	results := make(chan error, 2)
	source := feedbackTestSource(t)
	for _, key := range []string{"first", "second"} {
		go func() {
			<-started
			_, err := f.database.CreateFeedback(t.Context(), f.auth(), CreateFeedbackRequest{
				PreviewID: preview.ID, Service: "web", PagePath: "/settings",
				ReportText:     "The settings save is inconsistent",
				Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
				SourceAtReport: source, IdempotencyKey: key,
				Actor: FeedbackActor{Kind: "reviewer", VisitAllowed: true, SourceIP: "192.0.2.9"},
			}, f.now)
			results <- err
		}()
	}
	close(started)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.database.ListFeedbackEventsForTeam(t.Context(), f.project.TeamID, 0)
	if err != nil || len(page.Events) != 2 || page.Events[0].Cursor != 1 || page.Events[1].Cursor != 2 || page.EventCursor != 2 {
		t.Fatalf("concurrent creation event cursors = %+v, %v", page, err)
	}
}
