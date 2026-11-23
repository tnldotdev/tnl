package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/sourcestate"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type feedbackOutputMode string

const (
	feedbackHuman  feedbackOutputMode = "human"
	feedbackJSON   feedbackOutputMode = "json"
	feedbackNDJSON feedbackOutputMode = "ndjson"
)

type feedbackCommand struct {
	List    feedbackListCommand
	Inspect feedbackInspectCommand
	Watch   feedbackWatchCommand
	Reply   feedbackReplyCommand
	Update  feedbackUpdateCommand
	Resolve feedbackResolveCommand
	Reopen  feedbackReopenCommand
	Delete  feedbackDeleteCommand
}

type feedbackListCommand struct {
	scopedTeamFlags `embed:""`
	Output          feedbackOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type feedbackInspectCommand struct {
	scopedTeamFlags `embed:""`
	FeedbackID      string             `arg:"" name:"feedback-id" required:"" help:"Feedback thread ID."`
	Output          feedbackOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type feedbackWatchCommand struct {
	scopedTeamFlags `embed:""`
	After           uint64             `name:"after" default:"0" help:"Resume after this event cursor."`
	Output          feedbackOutputMode `name:"output" enum:"human,ndjson" default:"ndjson" help:"Output format: ${enum}."`
}

type feedbackMutationCommand struct {
	scopedTeamFlags `embed:""`
	FeedbackID      string             `arg:"" name:"feedback-id" required:"" help:"Feedback thread ID."`
	Message         string             `name:"message" help:"Reply, update, or optional status-change note."`
	Output          feedbackOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type feedbackReplyCommand struct {
	feedbackMutationCommand `embed:""`
}
type feedbackUpdateCommand struct {
	feedbackMutationCommand `embed:""`
}
type feedbackResolveCommand struct {
	feedbackMutationCommand `embed:""`
}

type feedbackReopenCommand struct {
	feedbackMutationCommand `embed:""`
}
type feedbackDeleteCommand struct {
	scopedTeamFlags `embed:""`
	FeedbackID      string `arg:"" name:"feedback-id" required:"" help:"Local feedback thread ID."`
}

func localFeedback(ctx context.Context, session *clientteam.Session, project projectConfiguration, preview string) (*clientstate.FeedbackStore, error) {
	if !project.Found() || project.Root == "" || preview == "" {
		return nil, failure.Wrap("select local feedback", failure.PreviewNotSaved, errors.New("run from the project/worktree that owns the preview; start a configured app service first"))
	}
	return session.Store().Feedback(ctx, project.LocalPublicationIdentity().Fingerprint, preview, func(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
		return session.Authenticated().Control.AuthorizeImplementerFeedback(ctx, controlv1.AuthorizeImplementerFeedbackRequest{PreviewId: preview, ServiceId: service, Operation: controlv1.FeedbackOperation(operation)})
	})
}

func runFeedbackDelete(ctx context.Context, flags feedbackDeleteCommand, project projectConfiguration, output, diagnostics io.Writer) (retErr error) {
	defer func() { retErr = localFeedbackFailure(retErr) }()
	if err := validFeedbackID(flags.FeedbackID); err != nil {
		return err
	}
	session, _, preview, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	local, err := localFeedback(ctx, session, project, preview)
	if err != nil {
		return err
	}
	if err = local.Delete(ctx, flags.FeedbackID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl feedback delete", "deleted", "", clioutput.Fields(clioutput.Field{Label: "feedback ID", Value: flags.FeedbackID}))
}

func localFeedbackFailure(err error) error {
	switch {
	case errors.Is(err, clientstate.ErrFeedbackInvalid):
		return failure.Wrap("validate local feedback", failure.FeedbackInputInvalid, err)
	case errors.Is(err, clientstate.ErrFeedbackNotFound):
		return failure.Wrap("read local feedback", failure.ServerResourceNotFound, err)
	case errors.Is(err, clientstate.ErrFeedbackAccess):
		return failure.Wrap("authorize local feedback", failure.ServerDenied, err)
	case errors.Is(err, clientstate.ErrFeedbackState), errors.Is(err, clientstate.ErrFeedbackIdempotency):
		return failure.Wrap("change local feedback", failure.ServerConflict, err)
	default:
		return err
	}
}

type feedbackListResult struct {
	SchemaVersion int                               `json:"schema_version"`
	Threads       []controlv1.FeedbackThreadSummary `json:"threads"`
	EventCursor   uint64                            `json:"event_cursor"`
}

type feedbackLocalProject struct {
	Path                string                 `json:"path"`
	MatchesPreview      bool                   `json:"matches_preview"`
	SourceState         *controlv1.SourceState `json:"source_state,omitempty"`
	MatchesReportSource bool                   `json:"matches_report_source"`
	Comparison          string                 `json:"comparison"`
}

type feedbackInspectResult struct {
	controlv1.FeedbackThread
	Events       []controlv1.FeedbackEvent `json:"events"`
	EventCursor  uint64                    `json:"event_cursor"`
	LocalProject feedbackLocalProject      `json:"local_project"`
}

func feedbackSession(ctx context.Context, flags scopedTeamFlags, project projectConfiguration, command string, diagnostics io.Writer) (*clientteam.Session, string, string, error) {
	session, err := openTeamSession(ctx, flags.selection(), command, diagnostics)
	if err != nil {
		return nil, "", "", err
	}
	current, err := session.Current(ctx)
	if err != nil {
		session.Close()
		return nil, "", "", err
	}
	previewID := ""
	if project.Found() && project.Root != "" {
		id, found, readErr := session.Store().PreviewID(ctx, current.Team().Id, project.LocalWorktreeKey())
		if readErr != nil {
			session.Close()
			return nil, "", "", readErr
		}
		if found {
			previewID = id
		}
	}
	return session, current.Team().Id, previewID, nil
}

func validFeedbackID(id string) error {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return failure.Wrap("validate feedback ID", failure.FeedbackInputInvalid, errors.New("provide a feedback thread ID from tnl feedback list"))
	}
	return nil
}

func runFeedbackList(ctx context.Context, flags feedbackListCommand, project projectConfiguration, output, diagnostics io.Writer) (retErr error) {
	defer func() { retErr = localFeedbackFailure(retErr) }()
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if project.Found() && previewID == "" {
		return failure.Wrap("read project preview", failure.PreviewNotSaved, errors.New("preview is not saved for this project; start a configured app service first"))
	}
	local, err := localFeedback(ctx, session, project, previewID)
	if err != nil {
		return err
	}
	threads := []controlv1.FeedbackThreadSummary{}
	var cursor uint64
	pageCursor := ""
	for {
		page, err := local.List(ctx, "", "", "", pageCursor)
		if err != nil {
			return err
		}
		if pageCursor == "" {
			cursor = uint64(page.EventCursor)
		}
		threads = append(threads, page.Threads...)
		if page.NextCursor == nil {
			break
		}
		pageCursor = *page.NextCursor
	}
	if flags.Output == feedbackJSON {
		return failure.Wrap("write feedback list", failure.OutputUnavailable, json.NewEncoder(output).Encode(feedbackListResult{SchemaVersion: 1, Threads: threads, EventCursor: cursor}))
	}
	blocks := make([]clioutput.Block, 0, len(threads)+1)
	for _, thread := range threads {
		blocks = append(blocks, clioutput.Section(thread.Id, clioutput.Fields(
			clioutput.Field{Label: "state", Value: string(thread.State)},
			clioutput.Field{Label: "service", Value: thread.Scope.Service},
			clioutput.Field{Label: "page", Value: thread.Scope.PagePath},
			clioutput.Field{Label: "author", Value: feedbackAuthorLabel(thread.Report.Author)},
			clioutput.Field{Label: "report", Value: thread.Report.Text},
		)))
	}
	blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "watch after", Value: strconv.FormatUint(cursor, 10)}))
	return writeHumanFrame(output, "tnl feedback list", countState(len(threads), "thread", "threads"), "", blocks...)
}

type feedbackThreadReader interface {
	Events(context.Context, string, string, uint64) (controlv1.FeedbackEventPage, error)
}

func readFeedbackHistory(ctx context.Context, client feedbackThreadReader, id string) ([]controlv1.FeedbackEvent, uint64, error) {
	events := make([]controlv1.FeedbackEvent, 0)
	var after, watermark uint64
	for {
		page, err := client.Events(ctx, "", id, after)
		if err != nil {
			return nil, 0, err
		}
		if page.SchemaVersion != 1 {
			return nil, 0, failure.Wrap("read feedback history", failure.ServerResponseInvalid, errors.New("feedback history format is not supported by this client"))
		}
		if watermark == 0 {
			watermark = uint64(page.EventCursor)
		}
		for _, event := range page.Events {
			if event.SchemaVersion != 1 {
				return nil, 0, failure.Wrap("read feedback event", failure.ServerResponseInvalid, errors.New("feedback event format is not supported by this client"))
			}
			if uint64(event.Cursor) > watermark {
				return events, watermark, nil
			}
			if uint64(event.Cursor) <= after {
				return nil, 0, failure.Wrap("read feedback events", failure.ServerResponseInvalid, errors.New("server returned repeated feedback events"))
			}
			events = append(events, event)
			after = uint64(event.Cursor)
		}
		if page.NextCursor == nil {
			return events, watermark, nil
		}
		if uint64(*page.NextCursor) < after || uint64(*page.NextCursor) > watermark {
			return nil, 0, failure.Wrap("read feedback cursor", failure.ServerResponseInvalid, errors.New("server returned an invalid feedback cursor"))
		}
		if uint64(*page.NextCursor) == after && len(page.Events) == 0 {
			return nil, 0, failure.Wrap("read feedback page", failure.ServerResponseInvalid, errors.New("server repeated an empty feedback page"))
		}
		after = uint64(*page.NextCursor)
	}
}

func compareFeedbackSource(ctx context.Context, project projectConfiguration, previewID string, thread controlv1.FeedbackThread) feedbackLocalProject {
	result := feedbackLocalProject{Path: project.Root, MatchesPreview: previewID != "" && previewID == thread.Scope.PreviewId, Comparison: "unavailable"}
	if project.Root == "" {
		return result
	}
	current, err := sourcestate.Capture(ctx, project.Root)
	if err == nil {
		result.SourceState = &current
	}
	if previewID == "" {
		return result
	}
	if !result.MatchesPreview {
		result.Comparison = "different preview"
		return result
	}
	if err != nil {
		result.Comparison = "inconclusive"
		return result
	}
	comparison := sourcestate.Compare(current, thread.SourceAtReport)
	result.MatchesReportSource = comparison == sourcestate.Matches
	result.Comparison = string(comparison)
	return result
}

func runFeedbackInspect(ctx context.Context, flags feedbackInspectCommand, project projectConfiguration, output, diagnostics io.Writer) (retErr error) {
	defer func() { retErr = localFeedbackFailure(retErr) }()
	if err := validFeedbackID(flags.FeedbackID); err != nil {
		return err
	}
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback inspect", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	local, err := localFeedback(ctx, session, project, previewID)
	if err != nil {
		return err
	}
	thread, err := local.GetFeedbackThread(ctx, flags.FeedbackID)
	if err != nil {
		return err
	}
	if thread.SchemaVersion != 1 {
		return failure.Wrap("inspect feedback", failure.ServerResponseInvalid, errors.New("feedback format is not supported by this client"))
	}
	events, cursor, err := readFeedbackHistory(ctx, local, flags.FeedbackID)
	if err != nil {
		return err
	}
	result := feedbackInspectResult{FeedbackThread: thread, Events: events, EventCursor: cursor, LocalProject: compareFeedbackSource(ctx, project, previewID, thread)}
	if flags.Output == feedbackJSON {
		return failure.Wrap("write feedback history", failure.OutputUnavailable, json.NewEncoder(output).Encode(result))
	}
	blocks := []clioutput.Block{
		clioutput.Fields(
			clioutput.Field{Label: "feedback ID", Value: thread.Id},
			clioutput.Field{Label: "state", Value: string(thread.State)},
			clioutput.Field{Label: "service", Value: thread.Scope.Service},
			clioutput.Field{Label: "page", Value: thread.Scope.PagePath},
			clioutput.Field{Label: "author", Value: feedbackAuthorLabel(thread.Report.Author)},
			clioutput.Field{Label: "report", Value: thread.Report.Text},
			clioutput.Field{Label: "element", Value: feedbackElementLabel(thread.Evidence.Element)},
			clioutput.Field{Label: "source", Value: result.LocalProject.Comparison},
			clioutput.Field{Label: "event cursor", Value: strconv.FormatUint(cursor, 10)},
		),
	}
	for _, event := range events {
		text := ""
		if event.Text != nil {
			text = *event.Text
		}
		blocks = append(blocks, clioutput.Section(strconv.FormatInt(event.Cursor, 10)+" "+string(event.Type), clioutput.Fields(
			clioutput.Field{Label: "by", Value: feedbackEventAuthorLabel(event)},
			clioutput.Field{Label: "message", Value: text},
		)))
	}
	return writeHumanFrame(output, "tnl feedback inspect", string(thread.State), "", blocks...)
}

func feedbackElementLabel(element *controlv1.FeedbackElement) string {
	if element != nil && element.Label != nil {
		return *element.Label
	}
	return "page"
}

func feedbackAuthorLabel(author *controlv1.FeedbackAuthor) string {
	if author == nil {
		return "anonymous"
	}
	if author.Verified {
		return author.DisplayName
	}
	return author.DisplayName + " (unverified)"
}

func feedbackEventAuthorLabel(event controlv1.FeedbackEvent) string {
	if event.Author != nil {
		return feedbackAuthorLabel(event.Author)
	}
	return string(event.Actor)
}

type feedbackEventReader interface {
	Events(context.Context, string, string, uint64) (controlv1.FeedbackEventPage, error)
	GetFeedbackThread(context.Context, string) (controlv1.FeedbackThread, error)
}

func pollFeedbackEvents(ctx context.Context, client feedbackEventReader, previewID string, cursor uint64, output io.Writer, mode feedbackOutputMode) (uint64, bool, error) {
	page, err := client.Events(ctx, "", "", cursor)
	if err != nil {
		return cursor, false, err
	}
	if page.SchemaVersion != 1 {
		return cursor, false, failure.Wrap("watch feedback", failure.ServerResponseInvalid, errors.New("feedback stream format is not supported by this client"))
	}
	encoder := json.NewEncoder(output)
	for _, event := range page.Events {
		if event.SchemaVersion != 1 {
			return cursor, false, failure.Wrap("watch feedback event", failure.ServerResponseInvalid, errors.New("feedback event format is not supported by this client"))
		}
		if event.Cursor <= 0 || uint64(event.Cursor) <= cursor {
			return cursor, false, failure.Wrap("watch feedback events", failure.ServerResponseInvalid, errors.New("server returned repeated feedback events"))
		}
		if previewID != "" {
			thread, readErr := client.GetFeedbackThread(ctx, event.FeedbackId)
			if readErr != nil {
				return cursor, false, readErr
			}
			if thread.Scope.PreviewId != previewID {
				cursor = uint64(event.Cursor)
				continue
			}
		}
		if mode == feedbackNDJSON {
			err = encoder.Encode(event)
		} else {
			text := ""
			if event.Text != nil {
				text = *event.Text
			}
			err = writeHumanFrame(output, "tnl feedback watch", string(event.Type), "", clioutput.Fields(
				clioutput.Field{Label: "feedback ID", Value: event.FeedbackId},
				clioutput.Field{Label: "cursor", Value: strconv.FormatInt(event.Cursor, 10)},
				clioutput.Field{Label: "by", Value: feedbackEventAuthorLabel(event)},
				clioutput.Field{Label: "message", Value: text},
			))
		}
		if err != nil {
			return cursor, false, failure.Wrap("write feedback event", failure.OutputUnavailable, err)
		}
		cursor = uint64(event.Cursor)
	}
	if page.NextCursor != nil {
		if *page.NextCursor < 0 || uint64(*page.NextCursor) <= cursor && len(page.Events) == 0 {
			return cursor, false, failure.Wrap("watch feedback cursor", failure.ServerResponseInvalid, errors.New("server returned an invalid feedback cursor"))
		}
		return max(cursor, uint64(*page.NextCursor)), true, nil
	}
	return max(cursor, uint64(page.EventCursor)), false, nil
}

func runFeedbackWatch(ctx context.Context, flags feedbackWatchCommand, project projectConfiguration, output, diagnostics io.Writer) (retErr error) {
	defer func() { retErr = localFeedbackFailure(retErr) }()
	if flags.After > math.MaxInt64 {
		return failure.Wrap("validate feedback cursor", failure.FeedbackInputInvalid, errors.New("feedback cursor is out of range"))
	}
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback watch", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if project.Found() && previewID == "" {
		return failure.Wrap("read project preview", failure.PreviewNotSaved, errors.New("preview is not saved for this project; start a configured app service first"))
	}
	local, err := localFeedback(ctx, session, project, previewID)
	if err != nil {
		return err
	}
	cursor := flags.After
	for {
		var more bool
		cursor, more, err = pollFeedbackEvents(ctx, local, previewID, cursor, output, flags.Output)
		if err != nil && !errors.Is(err, clientcontrol.ErrUnavailable) {
			return err
		}
		if more && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func runFeedbackMutation(ctx context.Context, flags feedbackMutationCommand, project projectConfiguration, kind string, output, diagnostics io.Writer) (retErr error) {
	defer func() { retErr = localFeedbackFailure(retErr) }()
	if err := validFeedbackID(flags.FeedbackID); err != nil {
		return err
	}
	message := strings.TrimSpace(flags.Message)
	if (kind == "reply" || kind == "update") && message == "" {
		return failure.Wrap("validate feedback message", failure.FeedbackInputInvalid, errors.New("provide a message for this feedback event"))
	}
	if len(message) > 4000 {
		return failure.Wrap("validate feedback message", failure.FeedbackInputInvalid, errors.New("feedback message must be at most 4000 bytes"))
	}
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback "+feedbackMutationName(kind), diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	local, err := localFeedback(ctx, session, project, previewID)
	if err != nil {
		return err
	}
	body := controlv1.AppendFeedbackEventRequest{Type: controlv1.FeedbackEventInputType(kind)}
	if message != "" {
		body.Text = &message
	}
	if kind == "update" {
		thread, err := local.GetFeedbackThread(ctx, flags.FeedbackID)
		if err != nil {
			return err
		}
		if project.Root == "" || previewID == "" || thread.Scope.PreviewId != previewID {
			return failure.Wrap("select feedback project", failure.PreviewStateConflict, errors.New("run the update from the project directory that owns this preview"))
		}
		source, err := sourcestate.Capture(ctx, project.Root)
		if err != nil {
			return err
		}
		body.SourceState = &source
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	event, err := local.AppendFeedbackEvent(ctx, flags.FeedbackID, key, body)
	if err != nil {
		return err
	}
	if flags.Output == feedbackJSON {
		return failure.Wrap("write feedback event", failure.OutputUnavailable, json.NewEncoder(output).Encode(event))
	}
	return writeHumanFrame(output, "tnl feedback "+feedbackMutationName(kind), "saved", "", clioutput.Fields(
		clioutput.Field{Label: "feedback ID", Value: flags.FeedbackID},
		clioutput.Field{Label: "event cursor", Value: strconv.FormatInt(event.Cursor, 10)},
	))
}

func feedbackMutationName(kind string) string {
	switch kind {
	case "update":
		return "update"
	case "thread.resolved":
		return "resolve"
	case "thread.reopened":
		return "reopen"
	default:
		return "reply"
	}
}

func (a *commandApp) newFeedbackCommand() *cobra.Command {
	f := a.flags
	cFeedback := &cobra.Command{Use: "feedback", Short: "Read and follow up on preview feedback.", GroupID: "manage"}
	cFeedbackList := &cobra.Command{Use: "list", Short: "List feedback for this project's preview."}
	a.leaf(cFeedbackList, &f.Feedback.List, func(call commandCall) error {
		return runFeedbackList(call.ctx, f.Feedback.List, call.project, a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackList)
	cFeedbackInspect := &cobra.Command{Use: "inspect", Short: "Read a report, events, and compare with your current source."}
	a.leaf(cFeedbackInspect, &f.Feedback.Inspect, func(call commandCall) error {
		return runFeedbackInspect(call.ctx, f.Feedback.Inspect, call.project, a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackInspect)
	cFeedbackWatch := &cobra.Command{Use: "watch", Short: "Follow ordered feedback events; resume after a cursor."}
	a.leaf(cFeedbackWatch, &f.Feedback.Watch, func(call commandCall) error {
		return runFeedbackWatch(call.ctx, f.Feedback.Watch, call.project, a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackWatch)
	cFeedbackReply := &cobra.Command{Use: "reply", Short: "Reply to a feedback thread."}
	a.leaf(cFeedbackReply, &f.Feedback.Reply, func(call commandCall) error {
		return runFeedbackMutation(call.ctx, f.Feedback.Reply.feedbackMutationCommand, call.project, "reply", a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackReply)
	cFeedbackUpdate := &cobra.Command{Use: "update", Short: "Post an update with the current source state."}
	a.leaf(cFeedbackUpdate, &f.Feedback.Update, func(call commandCall) error {
		return runFeedbackMutation(call.ctx, f.Feedback.Update.feedbackMutationCommand, call.project, "update", a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackUpdate)
	cFeedbackResolve := &cobra.Command{Use: "resolve", Short: "Resolve an open feedback thread."}
	a.leaf(cFeedbackResolve, &f.Feedback.Resolve, func(call commandCall) error {
		return runFeedbackMutation(call.ctx, f.Feedback.Resolve.feedbackMutationCommand, call.project, "thread.resolved", a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackResolve)
	cFeedbackReopen := &cobra.Command{Use: "reopen", Short: "Reopen a resolved feedback thread."}
	a.leaf(cFeedbackReopen, &f.Feedback.Reopen, func(call commandCall) error {
		return runFeedbackMutation(call.ctx, f.Feedback.Reopen.feedbackMutationCommand, call.project, "thread.reopened", a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackReopen)
	cFeedbackDelete := &cobra.Command{Use: "delete", Short: "Delete a local thread, report, evidence, source snapshots, and history."}
	a.leaf(cFeedbackDelete, &f.Feedback.Delete, func(call commandCall) error {
		return runFeedbackDelete(call.ctx, f.Feedback.Delete, call.project, a.out, a.errOut)
	})
	cFeedback.AddCommand(cFeedbackDelete)
	return cFeedback
}
