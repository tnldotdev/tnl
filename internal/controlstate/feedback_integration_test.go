package controlstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func feedbackTestCheckout(t *testing.T) json.RawMessage {
	t.Helper()
	digest := sha256.Sum256([]byte("checkout"))
	marker, err := json.Marshal(CheckoutMarker{
		SchemaVersion: 1,
		HeadCommit:    strings.Repeat("a", 40), Branch: "perf",
		ChangedFiles: []FeedbackChangedFile{{Path: "apps/web/Profile.tsx", Status: "modified", ContentSHA256: "sha256:" + hex.EncodeToString(digest[:])}},
		Fingerprint:  "sha256:" + hex.EncodeToString(digest[:]), Complete: new(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	return marker
}

func TestIntegrationFeedbackReportEventsResolveReopenAndResume(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	preview, err := database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "feedback", now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EnableShareAccess(t.Context(), f.authentication(), preview.ID); err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdefghijklmnopqrstuv")
	share, err := database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "feedback-share", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(time.Hour),
		PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie := []byte(strings.Repeat("c", 32))
	hash := sha256.Sum256(cookie)
	if _, err := controlstatedb.New(database.pool).InsertShareCookie(t.Context(), controlstatedb.InsertShareCookieParams{
		TokenDigest: hash[:], PublicURLID: f.setup.PublicURLID, CreatedAt: timestamptz(now), ShareID: share.ID,
	}); err != nil {
		t.Fatal(err)
	}
	actor := FeedbackActor{Kind: "reviewer", ShareID: share.ID, CookieSecret: cookie}
	marker := feedbackTestCheckout(t)
	request := CreateFeedbackRequest{
		PreviewID: preview.ID, Service: "web", PagePath: "/settings/profile",
		ReportText: "Save says it worked, but changes disappear after reload.", AuthorDisplayName: "Sam",
		Anchor:           json.RawMessage(`{"schema_version":1,"selectors":["[data-testid=save]"],"x":0.5,"y":0.5}`),
		Evidence:         json.RawMessage(`{"schema_version":1,"element":{"role":"button","label":"Save changes","html":"<button onclick='steal()' data-testid='save'>Save</button><script>steal()</script>"},"actions":[{"type":"click","label":"Save changes"}],"failed_requests":[{"method":"POST","path":"/api/profile","status":500,"duration_ms":184}]}`),
		CheckoutAtReport: marker, IdempotencyKey: "first-report", Actor: actor,
	}
	thread, err := database.CreateFeedback(t.Context(), f.authentication(), request, now)
	if err != nil || thread.ID == "" || thread.SchemaVersion != 1 || thread.State != FeedbackOpen || !strings.Contains(string(thread.Evidence), "data-testid") ||
		strings.Contains(string(thread.Evidence), "onclick") || strings.Contains(string(thread.Evidence), "<script>") {
		t.Fatalf("submitted report = %+v, %v", thread, err)
	}
	firstPage, err := database.ListFeedbackEventsForTeam(t.Context(), f.request.TeamID, 0)
	if err != nil || len(firstPage.Events) != 1 || firstPage.Events[0].Type != FeedbackCreated || firstPage.Events[0].Cursor == 0 {
		t.Fatalf("initial event = %+v, %v", firstPage, err)
	}
	retry, err := database.CreateFeedback(t.Context(), f.authentication(), request, now.Add(time.Second))
	if err != nil || retry.ID != thread.ID {
		t.Fatalf("retried report = %+v, %v", retry, err)
	}
	altered := request
	altered.ReportText = "different text"
	if _, err := database.CreateFeedback(t.Context(), f.authentication(), altered, now); !errors.Is(err, ErrFeedbackIdempotency) {
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
	implementer := FeedbackActor{Kind: "implementer", IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2}
	wrongImplementer := AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackUpdate, Text: "Updated the copy", CheckoutMarker: marker,
		IdempotencyKey: "wrong-owner", Actor: FeedbackActor{Kind: "implementer", IdentityID: "different-identity", PolicyRevision: 1, ExpectedMutationRevision: 2},
	}
	if _, err := database.AppendFeedback(t.Context(), wrongImplementer, now.Add(2*time.Second)); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("unrelated implementer changed feedback: %v", err)
	}
	update := AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackUpdate, Text: "Updated the save handler.",
		CheckoutMarker: marker, IdempotencyKey: "update", Actor: implementer,
	}
	updated, err := database.AppendFeedback(t.Context(), update, now.Add(3*time.Second))
	if err != nil || len(updated.CheckoutMarker) == 0 {
		t.Fatalf("checkout update = %+v, %v", updated, err)
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
		string(current.CheckoutAtReport) != string(thread.CheckoutAtReport) {
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
	if _, err := database.RevokeShare(t.Context(), share.ID, f.request.ActingIdentityID, now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AppendFeedback(t.Context(), AppendFeedbackRequest{
		FeedbackID: thread.ID, Type: FeedbackReply, Text: "late", IdempotencyKey: "revoked-reviewer", Actor: actor,
	}, now.Add(8*time.Second)); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("revoked reviewer wrote feedback: %v", err)
	}
	events, err := database.ListFeedbackEventsForTeam(t.Context(), f.request.TeamID, firstPage.EventCursor)
	if err != nil || len(events.Events) != 6 || events.EventCursor != events.Events[len(events.Events)-1].Cursor {
		t.Fatalf("resumed events = %+v, %v", events, err)
	}
	for index, event := range events.Events {
		if event.Cursor != firstPage.EventCursor+uint64(index)+1 {
			t.Fatalf("feedback cursor gap at %d: %+v", index, events.Events)
		}
	}
	listed, err := database.ListFeedbackForPage(t.Context(), preview.ID, f.setup.PublicURLID, "/settings/profile", "")
	if err != nil || len(listed.Threads) != 1 || listed.Threads[0].State != FeedbackOpen {
		t.Fatalf("page feedback = %+v, %v", listed, err)
	}
}

func TestIntegrationFeedbackCursorsOrderConcurrentReports(t *testing.T) {
	f := newPublishRunFixture(t)
	preview, err := f.database.CreatePreview(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "concurrent-reports", f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: f.setup.PublicURLID, TeamID: f.request.TeamID,
		IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	results := make(chan error, 2)
	marker := feedbackTestCheckout(t)
	for _, key := range []string{"first", "second"} {
		go func() {
			<-started
			_, err := f.database.CreateFeedback(t.Context(), f.authentication(), CreateFeedbackRequest{
				PreviewID: preview.ID, Service: "web", PagePath: "/settings",
				ReportText:       "The settings save is inconsistent",
				Evidence:         json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
				CheckoutAtReport: marker, IdempotencyKey: key,
				Actor: FeedbackActor{Kind: "reviewer", AllowedIP: true},
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
	page, err := f.database.ListFeedbackEventsForTeam(t.Context(), f.request.TeamID, 0)
	if err != nil || len(page.Events) != 2 || page.Events[0].Cursor != 1 || page.Events[1].Cursor != 2 || page.EventCursor != 2 {
		t.Fatalf("concurrent creation event cursors = %+v, %v", page, err)
	}
}
