package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/checkoutmarker"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type feedbackOutputMode string

const (
	feedbackHuman  feedbackOutputMode = "human"
	feedbackJSON   feedbackOutputMode = "json"
	feedbackNDJSON feedbackOutputMode = "ndjson"
)

type feedbackCommand struct {
	List    feedbackListCommand    `cmd:"" help:"List feedback for this checkout."`
	Inspect feedbackInspectCommand `cmd:"" help:"Read a report, events, and local checkout comparison."`
	Watch   feedbackWatchCommand   `cmd:"" help:"Follow ordered feedback events; resume after a cursor."`
	Reply   feedbackReplyCommand   `cmd:"" help:"Reply to a feedback thread."`
	Update  feedbackUpdateCommand  `cmd:"" help:"Post an update with the current checkout marker."`
	Resolve feedbackResolveCommand `cmd:"" help:"Resolve an open feedback thread."`
	Reopen  feedbackReopenCommand  `cmd:"" help:"Reopen a resolved feedback thread."`
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

type feedbackListResult struct {
	Threads     []controlv1.FeedbackThreadSummary `json:"threads"`
	EventCursor uint64                            `json:"event_cursor"`
}

type feedbackLocalWorktree struct {
	Path                  string `json:"path"`
	MatchesPreview        bool   `json:"matches_preview"`
	MatchesReportCheckout bool   `json:"matches_report_checkout"`
	Comparison            string `json:"comparison"`
}

type feedbackInspectResult struct {
	controlv1.FeedbackThread
	Events        []controlv1.FeedbackEvent `json:"events"`
	EventCursor   uint64                    `json:"event_cursor"`
	LocalWorktree feedbackLocalWorktree     `json:"local_worktree"`
}

func feedbackSession(ctx context.Context, flags scopedTeamFlags, project projectConfiguration, command string, diagnostics io.Writer) (*teamSession, string, string, error) {
	session, err := openTeamSession(ctx, flags.selection(), command, diagnostics)
	if err != nil {
		return nil, "", "", err
	}
	current, err := session.current(ctx)
	if err != nil {
		session.Close()
		return nil, "", "", err
	}
	previewID := ""
	if project.Found() && project.Root != "" {
		id, found, readErr := session.store.PreviewID(ctx, current.team.Id, project.Root)
		if readErr != nil {
			session.Close()
			return nil, "", "", readErr
		}
		if found {
			previewID = id
		}
	}
	return session, current.team.Id, previewID, nil
}

func validFeedbackID(id string) error {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return errors.New("provide a feedback thread ID from tnl feedback list")
	}
	return nil
}

func runFeedbackList(ctx context.Context, flags feedbackListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	session, teamID, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if project.Found() && previewID == "" {
		return errors.New("preview is not saved for this checkout; run tnl dev first")
	}
	threads, cursor, err := session.authenticated.Control.ListFeedbackThreads(ctx, teamID)
	if err != nil {
		return err
	}
	threads = filterFeedbackPreview(threads, previewID)
	if flags.Output == feedbackJSON {
		return json.NewEncoder(output).Encode(feedbackListResult{Threads: threads, EventCursor: cursor})
	}
	blocks := make([]clioutput.Block, 0, len(threads)+1)
	for _, thread := range threads {
		blocks = append(blocks, clioutput.Section(thread.Id, clioutput.Fields(
			clioutput.Field{Label: "state", Value: string(thread.State)},
			clioutput.Field{Label: "service", Value: thread.Scope.Service},
			clioutput.Field{Label: "page", Value: thread.Scope.PagePath},
			clioutput.Field{Label: "report", Value: thread.Report.Text},
		)))
	}
	blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "watch after", Value: strconv.FormatUint(cursor, 10)}))
	return writeHumanFrame(output, "tnl feedback list", countState(len(threads), "thread", "threads"), "", blocks...)
}

func filterFeedbackPreview(threads []controlv1.FeedbackThreadSummary, previewID string) []controlv1.FeedbackThreadSummary {
	if previewID == "" {
		return threads
	}
	return slices.DeleteFunc(threads, func(thread controlv1.FeedbackThreadSummary) bool {
		return thread.Scope.PreviewId != previewID
	})
}

type feedbackThreadReader interface {
	ListFeedbackThreadEvents(context.Context, string, uint64) (controlv1.FeedbackEventPage, error)
}

func readFeedbackHistory(ctx context.Context, client feedbackThreadReader, id string) ([]controlv1.FeedbackEvent, uint64, error) {
	events := make([]controlv1.FeedbackEvent, 0)
	var after, watermark uint64
	for {
		page, err := client.ListFeedbackThreadEvents(ctx, id, after)
		if err != nil {
			return nil, 0, err
		}
		if watermark == 0 {
			watermark = uint64(page.EventCursor)
		}
		for _, event := range page.Events {
			if uint64(event.Cursor) > watermark {
				return events, watermark, nil
			}
			if uint64(event.Cursor) <= after {
				return nil, 0, errors.New("server returned repeated feedback events")
			}
			events = append(events, event)
			after = uint64(event.Cursor)
		}
		if page.NextCursor == nil {
			return events, watermark, nil
		}
		if uint64(*page.NextCursor) < after || uint64(*page.NextCursor) > watermark {
			return nil, 0, errors.New("server returned an invalid feedback cursor")
		}
		if uint64(*page.NextCursor) == after && len(page.Events) == 0 {
			return nil, 0, errors.New("server repeated an empty feedback page")
		}
		after = uint64(*page.NextCursor)
	}
}

func compareFeedbackCheckout(ctx context.Context, project projectConfiguration, previewID string, thread controlv1.FeedbackThread) feedbackLocalWorktree {
	result := feedbackLocalWorktree{Path: project.Root, MatchesPreview: previewID != "" && previewID == thread.Scope.PreviewId, Comparison: "unavailable"}
	if project.Root == "" || previewID == "" {
		return result
	}
	if !result.MatchesPreview {
		result.Comparison = "different preview"
		return result
	}
	current, err := checkoutmarker.Capture(ctx, project.Root)
	if err != nil || !current.Complete || !thread.CheckoutAtReport.Complete {
		result.Comparison = "inconclusive"
		return result
	}
	result.MatchesReportCheckout = current.HeadCommit == thread.CheckoutAtReport.HeadCommit && current.Fingerprint == thread.CheckoutAtReport.Fingerprint
	result.Comparison = "different"
	if result.MatchesReportCheckout {
		result.Comparison = "matches"
	}
	return result
}

func runFeedbackInspect(ctx context.Context, flags feedbackInspectCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if err := validFeedbackID(flags.FeedbackID); err != nil {
		return err
	}
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback inspect", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	thread, err := session.authenticated.Control.GetFeedbackThread(ctx, flags.FeedbackID)
	if err != nil {
		return err
	}
	events, cursor, err := readFeedbackHistory(ctx, session.authenticated.Control, flags.FeedbackID)
	if err != nil {
		return err
	}
	result := feedbackInspectResult{FeedbackThread: thread, Events: events, EventCursor: cursor, LocalWorktree: compareFeedbackCheckout(ctx, project, previewID, thread)}
	if flags.Output == feedbackJSON {
		return json.NewEncoder(output).Encode(result)
	}
	blocks := []clioutput.Block{
		clioutput.Fields(
			clioutput.Field{Label: "feedback ID", Value: thread.Id},
			clioutput.Field{Label: "state", Value: string(thread.State)},
			clioutput.Field{Label: "service", Value: thread.Scope.Service},
			clioutput.Field{Label: "page", Value: thread.Scope.PagePath},
			clioutput.Field{Label: "report", Value: thread.Report.Text},
			clioutput.Field{Label: "element", Value: feedbackElementLabel(thread.Element)},
			clioutput.Field{Label: "checkout", Value: result.LocalWorktree.Comparison},
			clioutput.Field{Label: "event cursor", Value: strconv.FormatUint(cursor, 10)},
		),
	}
	for _, event := range events {
		text := ""
		if event.Text != nil {
			text = *event.Text
		}
		blocks = append(blocks, clioutput.Section(strconv.FormatInt(event.Cursor, 10)+" "+string(event.Type), clioutput.Text(text)))
	}
	return writeHumanFrame(output, "tnl feedback inspect", string(thread.State), "", blocks...)
}

func feedbackElementLabel(element controlv1.FeedbackElement) string {
	if element.Label != nil {
		return *element.Label
	}
	return "page"
}

type feedbackEventReader interface {
	ListFeedbackEvents(context.Context, string, uint64) (controlv1.FeedbackEventPage, error)
	GetFeedbackThread(context.Context, string) (controlv1.FeedbackThread, error)
}

func pollFeedbackEvents(ctx context.Context, client feedbackEventReader, teamID, previewID string, cursor uint64, output io.Writer, mode feedbackOutputMode) (uint64, bool, error) {
	page, err := client.ListFeedbackEvents(ctx, teamID, cursor)
	if err != nil {
		return cursor, false, err
	}
	encoder := json.NewEncoder(output)
	for _, event := range page.Events {
		if event.Cursor <= 0 || uint64(event.Cursor) <= cursor {
			return cursor, false, errors.New("server returned repeated feedback events")
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
				clioutput.Field{Label: "message", Value: text},
			))
		}
		if err != nil {
			return cursor, false, err
		}
		cursor = uint64(event.Cursor)
	}
	if page.NextCursor != nil {
		if *page.NextCursor < 0 || uint64(*page.NextCursor) <= cursor && len(page.Events) == 0 {
			return cursor, false, errors.New("server returned an invalid feedback cursor")
		}
		return max(cursor, uint64(*page.NextCursor)), true, nil
	}
	return max(cursor, uint64(page.EventCursor)), false, nil
}

func runFeedbackWatch(ctx context.Context, flags feedbackWatchCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.After > math.MaxInt64 {
		return errors.New("feedback cursor is out of range")
	}
	session, teamID, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback watch", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if project.Found() && previewID == "" {
		return errors.New("preview is not saved for this checkout; run tnl dev first")
	}
	cursor := flags.After
	for {
		var more bool
		cursor, more, err = pollFeedbackEvents(ctx, session.authenticated.Control, teamID, previewID, cursor, output, flags.Output)
		if err != nil && !errors.Is(err, controlclient.ErrUnavailable) {
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

func runFeedbackMutation(ctx context.Context, flags feedbackMutationCommand, project projectConfiguration, kind string, output, diagnostics io.Writer) error {
	if err := validFeedbackID(flags.FeedbackID); err != nil {
		return err
	}
	message := strings.TrimSpace(flags.Message)
	if (kind == "reply" || kind == "update") && message == "" {
		return errors.New("provide a message for this feedback event")
	}
	if len(message) > 4000 {
		return errors.New("feedback message must be at most 4000 bytes")
	}
	session, _, previewID, err := feedbackSession(ctx, flags.scopedTeamFlags, project, "tnl feedback "+feedbackMutationName(kind), diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	body := controlv1.AppendFeedbackEventRequest{Type: controlv1.FeedbackEventType(kind)}
	if message != "" {
		body.Text = &message
	}
	if kind == "update" {
		thread, err := session.authenticated.Control.GetFeedbackThread(ctx, flags.FeedbackID)
		if err != nil {
			return err
		}
		if project.Root == "" || previewID == "" || thread.Scope.PreviewId != previewID {
			return errors.New("run the update from the checkout that owns this preview")
		}
		marker, err := checkoutmarker.Capture(ctx, project.Root)
		if err != nil {
			return err
		}
		body.CheckoutMarker = &marker
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	event, err := session.authenticated.Control.AppendFeedbackEvent(ctx, flags.FeedbackID, key, body)
	if err != nil {
		return err
	}
	if flags.Output == feedbackJSON {
		return json.NewEncoder(output).Encode(event)
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
