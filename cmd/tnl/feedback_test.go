package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type feedbackReadFixture struct {
	threadPages map[uint64]controlv1.FeedbackEventPage
	teamPages   map[uint64]controlv1.FeedbackEventPage
	threads     map[string]controlv1.FeedbackThread
}

func TestFeedbackValidationHasOwnedReasonBeforeAuthentication(t *testing.T) {
	var output bytes.Buffer
	err := run(t.Context(), []string{"--no-config", "feedback", "inspect", "--state-dir", filepath.Join(t.TempDir(), "state"), "not-a-feedback-id"}, &output, io.Discard)
	reason, definition, ok := failure.Describe(err)
	if !ok || reason != failure.FeedbackInputInvalid || definition.Class != failure.Invalid || output.Len() != 0 {
		t.Fatalf("feedback validation reason=%s class=%s output=%q", reason, definition.Class, output.String())
	}
}

func TestFeedbackCursorFailureIsAResponseErrorAndKeepsOutputCauses(t *testing.T) {
	fixture := feedbackReadFixture{teamPages: map[uint64]controlv1.FeedbackEventPage{
		0: {EventCursor: 1, Events: []controlv1.FeedbackEvent{{Cursor: 0}}},
	}}
	_, _, err := pollFeedbackEvents(t.Context(), fixture, "tm_test", "", 0, io.Discard, feedbackNDJSON)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
		t.Fatalf("invalid cursor classified as %v", err)
	}
	fixture.teamPages[0] = controlv1.FeedbackEventPage{EventCursor: 1, Events: []controlv1.FeedbackEvent{{Cursor: 1}}}
	cause := errors.New("output pipe closed")
	_, _, err = pollFeedbackEvents(t.Context(), fixture, "tm_test", "", 0, failingFeedbackWriter{cause}, feedbackNDJSON)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.OutputUnavailable || !errors.Is(err, cause) {
		t.Fatalf("output failure classified as %v", err)
	}
}

type failingFeedbackWriter struct{ err error }

func (w failingFeedbackWriter) Write([]byte) (int, error) { return 0, w.err }

func (f feedbackReadFixture) ListFeedbackThreadEvents(_ context.Context, _ string, after uint64) (controlv1.FeedbackEventPage, error) {
	page, found := f.threadPages[after]
	if !found {
		return controlv1.FeedbackEventPage{}, errors.New("unexpected history cursor")
	}
	page.SchemaVersion = 1
	page.Events = append([]controlv1.FeedbackEvent(nil), page.Events...)
	for index := range page.Events {
		page.Events[index].SchemaVersion = 1
	}
	return page, nil
}

func (f feedbackReadFixture) ListFeedbackEvents(_ context.Context, _ string, after uint64) (controlv1.FeedbackEventPage, error) {
	page, found := f.teamPages[after]
	if !found {
		return controlv1.FeedbackEventPage{}, errors.New("unexpected watch cursor")
	}
	page.SchemaVersion = 1
	page.Events = append([]controlv1.FeedbackEvent(nil), page.Events...)
	for index := range page.Events {
		page.Events[index].SchemaVersion = 1
	}
	return page, nil
}

func (f feedbackReadFixture) GetFeedbackThread(_ context.Context, id string) (controlv1.FeedbackThread, error) {
	thread, found := f.threads[id]
	if !found {
		return controlv1.FeedbackThread{}, errors.New("unexpected feedback thread")
	}
	return thread, nil
}

func TestFeedbackHistoryUsesOneSnapshotAcrossPages(t *testing.T) {
	first := int64(3)
	fixture := feedbackReadFixture{threadPages: map[uint64]controlv1.FeedbackEventPage{
		0: {EventCursor: 4, Events: []controlv1.FeedbackEvent{{Cursor: 1}, {Cursor: 3}}, NextCursor: &first},
		3: {EventCursor: 5, Events: []controlv1.FeedbackEvent{{Cursor: 4}, {Cursor: 5}}},
	}}
	events, watermark, err := readFeedbackHistory(t.Context(), fixture, "fb_report")
	if err != nil || len(events) != 3 || events[0].Cursor != 1 || events[1].Cursor != 3 || events[2].Cursor != 4 || watermark != 4 {
		t.Fatalf("history snapshot = %v, %d, %v", events, watermark, err)
	}
}

func TestFeedbackWatchResumesAfterInvisibleEventsAndPagination(t *testing.T) {
	first := int64(2)
	fixture := feedbackReadFixture{
		teamPages: map[uint64]controlv1.FeedbackEventPage{
			0: {EventCursor: 4, Events: []controlv1.FeedbackEvent{
				{Cursor: 1, FeedbackId: "fb_other", Type: "reply"},
				{Cursor: 2, FeedbackId: "fb_mine", Type: "reply"},
			}, NextCursor: &first},
			2: {EventCursor: 4, Events: []controlv1.FeedbackEvent{{Cursor: 4, FeedbackId: "fb_mine", Type: "thread.resolved"}}},
			4: {EventCursor: 4, Events: []controlv1.FeedbackEvent{}},
		},
		threads: map[string]controlv1.FeedbackThread{
			"fb_other": {Scope: controlv1.FeedbackScope{PreviewId: "pv_other"}},
			"fb_mine":  {Scope: controlv1.FeedbackScope{PreviewId: "pv_mine"}},
		},
	}
	var output bytes.Buffer
	cursor, more, err := pollFeedbackEvents(t.Context(), fixture, "team", "pv_mine", 0, &output, feedbackNDJSON)
	if err != nil || !more || cursor != 2 {
		t.Fatalf("first watch page cursor = %d, more = %v, error = %v", cursor, more, err)
	}
	cursor, more, err = pollFeedbackEvents(t.Context(), fixture, "team", "pv_mine", cursor, &output, feedbackNDJSON)
	if err != nil || more || cursor != 4 {
		t.Fatalf("second watch page cursor = %d, more = %v, error = %v", cursor, more, err)
	}
	cursor, more, err = pollFeedbackEvents(t.Context(), fixture, "team", "pv_mine", cursor, &output, feedbackNDJSON)
	if err != nil || more || cursor != 4 {
		t.Fatalf("idle watch cursor = %d, more = %v, error = %v", cursor, more, err)
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []int64{2, 4} {
		var event controlv1.FeedbackEvent
		if err := decoder.Decode(&event); err != nil || event.Cursor != want {
			t.Fatalf("watched event %d = %+v, %v", want, event, err)
		}
	}
	var extra controlv1.FeedbackEvent
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected duplicate watch event = %+v", extra)
	}
}

func TestFeedbackInspectKeepsReportAndAddsLocalComparison(t *testing.T) {
	thread := controlv1.FeedbackThread{
		SchemaVersion: 1,
		Id:            "fb_example", State: "open",
		Report: controlv1.FeedbackReport{Text: "original report"},
		Scope:  controlv1.FeedbackScope{PreviewId: "pv_mine"},
	}
	comparison := compareFeedbackSource(t.Context(), projectConfiguration{}, "", thread)
	result := feedbackInspectResult{FeedbackThread: thread, Events: []controlv1.FeedbackEvent{{Cursor: 8}}, LocalProject: comparison}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || string(fields["id"]) != `"fb_example"` ||
		!bytes.Contains(fields["report"], []byte("original report")) || !bytes.Contains(fields["local_project"], []byte(`"matches_preview":false`)) || len(fields["events"]) == 0 {
		t.Fatalf("inspect projection = %s, %v", encoded, err)
	}
}

func TestFeedbackInspectExposesIncompleteLocalSourceWithoutClaimingAMatch(t *testing.T) {
	thread := controlv1.FeedbackThread{Scope: controlv1.FeedbackScope{PreviewId: "pv_mine"}, SourceAtReport: controlv1.SourceState{SchemaVersion: 1, Complete: false}}
	local := compareFeedbackSource(t.Context(), projectConfiguration{Root: t.TempDir()}, "pv_mine", thread)
	if !local.MatchesPreview || local.MatchesReportSource || local.Comparison != "inconclusive" || local.SourceState == nil || local.SourceState.SchemaVersion != 1 || local.SourceState.Complete {
		t.Fatalf("inspect must expose current source and its incomplete comparison: %+v", local)
	}
}
