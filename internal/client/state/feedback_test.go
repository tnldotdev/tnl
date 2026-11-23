package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const feedbackPreview = "pv_0123456789abcdefghijkl"
const feedbackService = "svc_0123456789abcdefghijkl"
const feedbackRun = "srun_0123456789abcdefghijkl"

type localFeedbackFixture struct {
	store       *Store
	local       *FeedbackStore
	root        string
	mu          sync.Mutex
	actor, name string
	denied      bool
}

func newLocalFeedbackFixture(t *testing.T) *localFeedbackFixture {
	t.Helper()
	d := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := d.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	f := &localFeedbackFixture{store: store, root: t.TempDir(), actor: "reviewer", name: "Verified reviewer"}
	f.local = feedbackForDirectory(t, store, f.root, feedbackPreview, f.authorize)
	return f
}

func feedbackForDirectory(t *testing.T, store *Store, root, preview string, authorize FeedbackAuthorize) *FeedbackStore {
	t.Helper()
	project, _, err := store.database.LocalProjectIdentity(t.Context(), root, "")
	if err != nil {
		t.Fatal(err)
	}
	local, err := store.Feedback(t.Context(), project, preview, authorize)
	if err != nil {
		t.Fatal(err)
	}
	return local
}
func (f *localFeedbackFixture) authorize(_ context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied {
		return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
	}
	identity := "ident_0123456789abcdefghijkl"
	return controlv1.FeedbackAuthorization{PreviewId: feedbackPreview, ServiceId: service, ServiceRunId: feedbackRun, RunNumber: 1, Actor: f.actor, Operation: controlv1.FeedbackOperation(operation),
		Author: controlv1.FeedbackAuthor{IdentityId: &identity, DisplayName: f.name, Verified: true}, ExpiresAt: time.Now().Add(4 * time.Second)}, nil
}
func (f *localFeedbackFixture) report(t *testing.T) controlv1.CreateFeedbackReportRequest {
	t.Helper()
	body := controlv1.CreateFeedbackReportRequest{PreviewId: feedbackPreview, RunNumber: 1, Service: "web", PagePath: "/settings/profile", PageTitle: new("Profile settings")}
	body.Report.Text = "The save button does not work"
	if err := json.Unmarshal(feedbackTestSource(t), &body.SourceAtReport); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"schema_version":1,"actions":[],"failed_requests":[]}`), &body.Evidence); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestFeedbackReportEventsResolveReopenAndResume(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	ctx := t.Context()
	body := f.report(t)
	thread, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", body)
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.local.Events(ctx, "", "", 0)
	if err != nil || len(first.Events) != 1 || first.EventCursor != 1 || first.Events[0].Type != "thread.created" {
		t.Fatal(first, err)
	}
	retry, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", body)
	if err != nil || !reflect.DeepEqual(thread, retry) {
		t.Fatal("report retry changed the immutable report", retry, err)
	}
	altered := body
	altered.Report.Text = "different"
	if _, err = f.local.Create(ctx, feedbackService, feedbackRun, "report", altered); !errors.Is(err, ErrFeedbackIdempotency) {
		t.Fatal("report conflict accepted", err)
	}
	reply := controlv1.AppendFeedbackEventRequest{Type: "reply", Text: new("Still seeing this?")}
	answered, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "reply", reply)
	if err != nil || answered.Cursor != 2 {
		t.Fatal(answered, err)
	}
	duplicate, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "reply", reply)
	if err != nil || duplicate.Cursor != answered.Cursor {
		t.Fatal("reply retry duplicated an event", err)
	}
	update := controlv1.AppendFeedbackEventRequest{Type: "update", Text: new("Updated the save handler."), SourceState: &body.SourceAtReport}
	if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "forged-update", update); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("reviewer posted source update", err)
	}
	f.actor = "implementer"
	updated, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "update", update)
	if err != nil || updated.SourceState == nil || updated.Author == nil || !updated.Author.Verified {
		t.Fatal("implementer source update", updated, err)
	}
	f.actor = "reviewer"
	resolution, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "resolve", controlv1.AppendFeedbackEventRequest{Type: "thread.resolved", Text: new("Looks good")})
	if err != nil {
		t.Fatal(err)
	}
	beforeReply, err := f.local.GetFeedbackThread(ctx, thread.Id)
	if err != nil {
		t.Fatal(err)
	}
	clarification, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "resolved-reply", reply)
	if err != nil || clarification.Cursor != resolution.Cursor+1 || clarification.Author == nil || !clarification.Author.Verified {
		t.Fatal("authorized resolved reply", clarification, err)
	}
	duplicate, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "resolved-reply", reply)
	if err != nil || duplicate.Cursor != clarification.Cursor {
		t.Fatal("resolved reply retry duplicated an event", duplicate, err)
	}
	changed := reply
	changed.Text = new("Different intent")
	if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "resolved-reply", changed); !errors.Is(err, ErrFeedbackIdempotency) {
		t.Fatal("resolved reply retry accepted changed intent", err)
	}
	afterReply, err := f.local.GetFeedbackThread(ctx, thread.Id)
	if err != nil || afterReply.State != "resolved" || afterReply.MessageCount != beforeReply.MessageCount+1 || afterReply.LatestEventCursor != clarification.Cursor {
		t.Fatal("resolved reply changed state or lost activity", afterReply, err)
	}
	afterReply.MessageCount, afterReply.LatestEventCursor = beforeReply.MessageCount, beforeReply.LatestEventCursor
	if !reflect.DeepEqual(afterReply, beforeReply) {
		t.Fatal("resolved reply rewrote the immutable report", afterReply)
	}
	f.denied = true
	for _, key := range []string{"resolved-reply", "denied-reply"} {
		if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, key, reply); !errors.Is(err, ErrFeedbackAccess) {
			t.Fatal("resolved reply cached authority", key, err)
		}
	}
	f.denied = false
	current, err := f.local.GetFeedbackThread(ctx, thread.Id)
	if err != nil || current.State != "resolved" || current.LatestEventCursor != clarification.Cursor || current.MessageCount != 4 {
		t.Fatal("denied resolved reply changed content or cursor", current, err)
	}
	reopen := controlv1.AppendFeedbackEventRequest{Type: "thread.reopened", Text: new("One more suggestion")}
	reopened, err := f.local.AppendFeedbackEvent(ctx, thread.Id, "reopen", reopen)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "reopen", reopen)
	if err != nil || duplicate.Cursor != reopened.Cursor {
		t.Fatal("reopen retry duplicated event", err)
	}
	f.actor = "implementer"
	for _, kind := range []string{"thread.resolved", "thread.reopened"} {
		if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, kind, controlv1.AppendFeedbackEventRequest{Type: controlv1.FeedbackEventInputType(kind)}); err != nil {
			t.Fatal(err)
		}
	}
	f.denied = true
	if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "revoked", reply); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("revocation was cached", err)
	}
	if _, err = f.local.GetFeedbackThread(ctx, thread.Id); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("revoked author read feedback", err)
	}
	f.denied = false
	current, err = f.local.GetFeedbackThread(ctx, thread.Id)
	if err != nil || current.State != "open" || current.MessageCount != 4 || !reflect.DeepEqual(current.Report, thread.Report) || !reflect.DeepEqual(current.SourceAtReport, thread.SourceAtReport) {
		t.Fatal("immutable report changed", current, err)
	}
	events, err := f.local.Events(ctx, "", "", uint64(first.EventCursor))
	if err != nil || len(events.Events) != 7 || events.EventCursor != 8 {
		t.Fatal(events, err)
	}
	eventTypes := []controlv1.FeedbackEventType{"reply", "update", "thread.resolved", "reply", "thread.reopened", "thread.resolved", "thread.reopened"}
	for i, event := range events.Events {
		if event.Cursor != int64(i+2) || event.Type != eventTypes[i] {
			t.Fatal("cursor gap or reordered history", events)
		}
	}
	if !reflect.DeepEqual(events.Events[2], resolution) {
		t.Fatal("reply changed the explicit status event or timestamp")
	}
	for _, filter := range []struct {
		service, path, state string
		count                int
	}{
		{feedbackService, body.PagePath, "", 1}, {feedbackService, "", "open", 1}, {feedbackService, "", "resolved", 0}, {"svc_abcdefghijkl0123456789", "", "", 0},
	} {
		page, err := f.local.List(ctx, filter.service, filter.path, filter.state, "")
		if err != nil || len(page.Threads) != filter.count {
			t.Fatal("page filter changed", filter, page, err)
		}
		if filter.count == 1 && (page.Threads[0].LatestEventCursor != 8 || page.Threads[0].Scope.PageTitle == nil || *page.Threads[0].Scope.PageTitle != "Profile settings") {
			t.Fatal("summary activity", page)
		}
	}
	f.name = "Later name"
	if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "later-author", reply); err != nil {
		t.Fatal(err)
	}
	current, err = f.local.GetFeedbackThread(ctx, thread.Id)
	if err != nil || !reflect.DeepEqual(current.Report, thread.Report) {
		t.Fatal("new sign-in rewrote historical author", err)
	}
}

func TestFeedbackCursorsOrderConcurrentReports(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	body := f.report(t)
	start := make(chan struct{})
	done := make(chan error, 2)
	for _, key := range []string{"first", "second"} {
		go func() {
			<-start
			_, err := f.local.Create(t.Context(), feedbackService, feedbackRun, key, body)
			done <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.local.Events(t.Context(), "", "", 0)
	if err != nil || len(page.Events) != 2 || page.Events[0].Cursor != 1 || page.Events[1].Cursor != 2 || page.EventCursor != 2 {
		t.Fatal(page, err)
	}
}

func TestFeedbackDeletionIsCompleteScopedAndDoesNotRewind(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	ctx := t.Context()
	thread, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", f.report(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "reply", controlv1.AppendFeedbackEventRequest{Type: "reply", Text: new("follow-up")}); err != nil {
		t.Fatal(err)
	}
	other := feedbackForDirectory(t, f.store, t.TempDir(), feedbackPreview, f.authorize)
	if _, err = other.GetFeedbackThread(ctx, thread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("another worktree read the report", err)
	}
	if err = other.Delete(ctx, thread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("another worktree deleted the report", err)
	}
	if err = f.local.Delete(ctx, thread.Id); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("reviewer deleted feedback", err)
	}
	f.actor = "implementer"
	if err = f.local.Delete(ctx, thread.Id); err != nil {
		t.Fatal(err)
	}
	if _, err = f.local.GetFeedbackThread(ctx, thread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("deleted report retained", err)
	}
	var reports, events int
	if err = f.store.database.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM feedback_threads),(SELECT count(*) FROM feedback_events)`).Scan(&reports, &events); err != nil || reports != 0 || events != 0 {
		t.Fatal("deletion left content", reports, events, err)
	}
	page, err := f.local.Events(ctx, "", "", 0)
	if err != nil || len(page.Events) != 0 || page.EventCursor != 2 {
		t.Fatal("deletion reset cursor or kept history", page, err)
	}
	f.actor = "reviewer"
	next, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", f.report(t))
	if err != nil || next.Id == thread.Id || next.LatestEventCursor != 3 {
		t.Fatal("deletion retained idempotency data or rewound cursor", next, err)
	}
}

func TestFeedbackPersistenceAndServerPreviewDirectoryIsolation(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	ctx := t.Context()
	thread, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", f.report(t))
	if err != nil {
		t.Fatal(err)
	}
	root := f.store.database.Root()
	if err = f.store.database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	f.store, err = reopened.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "project")
	if err = os.Symlink(f.root, alias); err != nil {
		t.Fatal(err)
	}
	local := feedbackForDirectory(t, f.store, alias, feedbackPreview, f.authorize)
	if got, err := local.GetFeedbackThread(ctx, thread.Id); err != nil || !reflect.DeepEqual(got, thread) {
		t.Fatal("reopen or symlink lost the owned report", got, err)
	}
	otherServer, err := reopened.Server(ctx, "https://other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	independent := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	otherClient, err := independent.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct {
		store         *Store
		root, preview string
	}{
		{otherServer, f.root, feedbackPreview}, {otherClient, f.root, feedbackPreview}, {f.store, f.root, "pv_abcdefghijkl0123456789"}, {f.store, t.TempDir(), feedbackPreview},
	} {
		other := feedbackForDirectory(t, scope.store, scope.root, scope.preview, f.authorize)
		if _, err = other.GetFeedbackThread(ctx, thread.Id); !errors.Is(err, ErrFeedbackNotFound) {
			t.Fatal("feedback crossed a local ownership boundary", err)
		}
	}
}

func TestFeedbackDeadlineRecheckedAfterSQLiteStatements(t *testing.T) {
	for _, operation := range []string{"create", "append", "read", "list", "events", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := newLocalFeedbackFixture(t)
			ctx := t.Context()
			body := f.report(t)
			thread, err := f.local.Create(ctx, feedbackService, feedbackRun, "original", body)
			if err != nil {
				t.Fatal(err)
			}
			f.actor = "implementer"
			if operation == "create" {
				f.actor = "reviewer"
			}
			now := time.Now()
			var ticks atomic.Int32
			f.local.authorize = func(ctx context.Context, service, kind string) (controlv1.FeedbackAuthorization, error) {
				a, err := f.authorize(ctx, service, kind)
				a.ExpiresAt = now.Add(2 * time.Second)
				return a, err
			}
			f.store.database.now = func() time.Time {
				if ticks.Add(1) <= 3 {
					return now
				}
				return now.Add(3 * time.Second)
			}
			switch operation {
			case "create":
				_, err = f.local.Create(ctx, feedbackService, feedbackRun, "expired", body)
			case "append":
				_, err = f.local.AppendFeedbackEvent(ctx, thread.Id, "expired", controlv1.AppendFeedbackEventRequest{Type: "reply", Text: new("expired")})
			case "read":
				_, err = f.local.GetFeedbackThread(ctx, thread.Id)
			case "list":
				_, err = f.local.List(ctx, feedbackService, "", "", "")
			case "events":
				_, err = f.local.Events(ctx, feedbackService, thread.Id, 0)
			case "delete":
				err = f.local.Delete(ctx, thread.Id)
			}
			if !errors.Is(err, ErrFeedbackAccess) {
				t.Fatal("expired local authority survived SQL work", operation, err)
			}
			f.store.database.now = time.Now
			f.local.authorize = f.authorize
			current, err := f.local.GetFeedbackThread(ctx, thread.Id)
			if err != nil || current.LatestEventCursor != 1 || current.MessageCount != 1 {
				t.Fatal("expired operation changed or deleted content", current, err)
			}
			page, err := f.local.Events(ctx, "", "", 0)
			if err != nil || len(page.Events) != 1 || page.EventCursor != 1 {
				t.Fatal("expired operation committed an event or cursor", page, err)
			}
		})
	}
}

func TestFeedbackAuthorizationCanRefreshSharedClientState(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	f.local.authorize = func(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
		if err := f.store.SaveSelectedTeam(ctx, "tm_0123456789abcdefghijkl"); err != nil {
			return controlv1.FeedbackAuthorization{}, err
		}
		return f.authorize(ctx, service, operation)
	}
	thread, err := f.local.Create(ctx, feedbackService, feedbackRun, "report", f.report(t))
	if err != nil {
		t.Fatal("authorization waited on its own SQLite transaction", err)
	}
	if _, err = f.local.GetFeedbackThread(ctx, thread.Id); err != nil {
		t.Fatal("read authorization waited on its own SQLite transaction", err)
	}
}

func TestFeedbackRejectsUnboundAuthorAndDecisionBeforePersistence(t *testing.T) {
	for name, mutate := range map[string]func(*controlv1.FeedbackAuthorization){
		"preview":    func(a *controlv1.FeedbackAuthorization) { a.PreviewId = "pv_abcdefghijkl0123456789" },
		"service":    func(a *controlv1.FeedbackAuthorization) { a.ServiceId = "svc_abcdefghijkl0123456789" },
		"run":        func(a *controlv1.FeedbackAuthorization) { a.ServiceRunId = "srun_abcdefghijkl0123456789" },
		"run number": func(a *controlv1.FeedbackAuthorization) { a.RunNumber++ },
		"operation":  func(a *controlv1.FeedbackAuthorization) { a.Operation = "read" },
		"actor":      func(a *controlv1.FeedbackAuthorization) { a.Actor = "implementer" },
		"unverified": func(a *controlv1.FeedbackAuthorization) { a.Author.Verified = false },
		"anonymous":  func(a *controlv1.FeedbackAuthorization) { a.Author.IdentityId = nil },
		"name":       func(a *controlv1.FeedbackAuthorization) { a.Author.DisplayName = "" },
		"expired":    func(a *controlv1.FeedbackAuthorization) { a.ExpiresAt = time.Now().Add(-time.Second) },
		"extended":   func(a *controlv1.FeedbackAuthorization) { a.ExpiresAt = time.Now().Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newLocalFeedbackFixture(t)
			f.local.authorize = func(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
				a, err := f.authorize(ctx, service, operation)
				mutate(&a)
				return a, err
			}
			if _, err := f.local.Create(t.Context(), feedbackService, feedbackRun, "report", f.report(t)); !errors.Is(err, ErrFeedbackAccess) {
				t.Fatal("unchecked decision authorized a report", err)
			}
			var count int
			if err := f.store.database.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM feedback_threads)+(SELECT count(*) FROM feedback_events)+(SELECT sum(cursor) FROM feedback_clocks)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied decision persisted content or a cursor", count, err)
			}
		})
	}
}

func TestFeedbackDemoCleanupAndRetainedProjectContent(t *testing.T) {
	f := newLocalFeedbackFixture(t)
	ctx := t.Context()
	body := f.report(t)
	project, err := f.local.Create(ctx, feedbackService, feedbackRun, "project", body)
	if err != nil {
		t.Fatal(err)
	}
	retain := time.Now().Add(time.Hour)
	authorize := func(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
		a, err := f.authorize(ctx, service, operation)
		a.ContentExpiresAt = &retain
		return a, err
	}
	demo, err := f.store.DemoFeedback(ctx, feedbackPreview, authorize)
	if err != nil {
		t.Fatal(err)
	}
	demoThread, err := demo.Create(ctx, feedbackService, feedbackRun, "demo", body)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.DiscardDemoFeedback(ctx, feedbackPreview); err != nil {
		t.Fatal(err)
	}
	if _, err = demo.GetFeedbackThread(ctx, demoThread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("stopped demo retained content", err)
	}
	demo, err = f.store.DemoFeedback(ctx, feedbackPreview, authorize)
	if err != nil {
		t.Fatal(err)
	}
	demoThread, err = demo.Create(ctx, feedbackService, feedbackRun, "demo", body)
	if err != nil {
		t.Fatal(err)
	}
	f.store.database.now = func() time.Time { return retain.Add(time.Second) }
	if _, err = f.store.Feedback(ctx, f.local.project, feedbackPreview, f.authorize); err != nil {
		t.Fatal(err)
	}
	f.store.database.now = time.Now
	if _, err = demo.GetFeedbackThread(ctx, demoThread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("expired demo retained content", err)
	}
	if got, err := f.local.GetFeedbackThread(ctx, project.Id); err != nil || !reflect.DeepEqual(got, project) {
		t.Fatal("demo cleanup deleted project-owned content", got, err)
	}
	f.actor = "implementer"
	if _, err := f.local.AppendFeedbackEvent(ctx, project.Id, "retained-resolve", controlv1.AppendFeedbackEventRequest{Type: "thread.resolved"}); err != nil {
		t.Fatal(err)
	}
	reply, err := f.local.AppendFeedbackEvent(ctx, project.Id, "retained-reply", controlv1.AppendFeedbackEventRequest{Type: "reply", Text: new("A clarification after service deletion")})
	if err != nil || reply.Author == nil || !reply.Author.Verified {
		t.Fatal("retained resolved feedback rejected an authorized manager reply", reply, err)
	}
	retained, err := f.local.GetFeedbackThread(ctx, project.Id)
	if err != nil || retained.State != "resolved" || retained.MessageCount != 2 || !reflect.DeepEqual(retained.Report, project.Report) || !reflect.DeepEqual(retained.SourceAtReport, project.SourceAtReport) {
		t.Fatal("retained reply reopened feedback or changed the first report", retained, err)
	}
	history, err := f.local.Events(ctx, feedbackService, project.Id, 0)
	if err != nil || len(history.Events) != 3 || history.Events[0].Type != "thread.created" || history.Events[1].Type != "thread.resolved" ||
		history.Events[2].Type != "reply" || history.EventCursor != reply.Cursor {
		t.Fatal("retained feedback lost ordered history", history, err)
	}
	f.actor = "reviewer"
	demo, err = f.store.DemoFeedback(ctx, feedbackPreview, authorize)
	if err != nil {
		t.Fatal(err)
	}
	demoThread, err = demo.Create(ctx, feedbackService, feedbackRun, "crashed", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.database.db.ExecContext(ctx, `UPDATE feedback_clocks SET expires_at=? WHERE project_root=?`, time.Now().Add(-time.Second).UnixNano(), "demo/"+feedbackPreview); err != nil {
		t.Fatal(err)
	}
	root := f.store.database.Root()
	if err = f.store.database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	f.store, err = reopened.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	demo, err = f.store.DemoFeedback(ctx, feedbackPreview, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = demo.GetFeedbackThread(ctx, demoThread.Id); !errors.Is(err, ErrFeedbackNotFound) {
		t.Fatal("client-state reopen kept expired demo content", err)
	}
}
