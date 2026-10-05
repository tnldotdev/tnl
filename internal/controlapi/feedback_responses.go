package controlapi

import (
	"encoding/json"
	"fmt"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func feedbackScope(thread controlstate.FeedbackThread) controlv1.FeedbackScope {
	return controlv1.FeedbackScope{
		PreviewId: thread.PreviewID, PublicUrlId: thread.PublicURLID,
		PublishRunId: thread.PublishRunID, PublishRunNumber: int64(thread.PublishRunNumber),
		PagePath: thread.PagePath, Service: thread.Service,
	}
}

func feedbackReport(thread controlstate.FeedbackThread) controlv1.FeedbackReport {
	report := controlv1.FeedbackReport{Text: thread.ReportText, CreatedAt: thread.CreatedAt}
	if thread.AuthorDisplayName != "" {
		report.Author = &struct {
			DisplayName string `json:"display_name"`
			Verified    bool   `json:"verified"`
		}{DisplayName: thread.AuthorDisplayName, Verified: false}
	}
	return report
}

func feedbackThreadResponse(thread controlstate.FeedbackThread) (controlv1.FeedbackThread, error) {
	var element controlv1.FeedbackElement
	var evidence controlv1.FeedbackEvidence
	var marker controlv1.CheckoutMarker
	if err := json.Unmarshal(thread.Element, &element); err != nil {
		return controlv1.FeedbackThread{}, fmt.Errorf("decode stored feedback element: %w", err)
	}
	if err := json.Unmarshal(thread.Evidence, &evidence); err != nil {
		return controlv1.FeedbackThread{}, fmt.Errorf("decode stored feedback evidence: %w", err)
	}
	if err := json.Unmarshal(thread.CheckoutAtReport, &marker); err != nil {
		return controlv1.FeedbackThread{}, fmt.Errorf("decode stored checkout marker: %w", err)
	}
	return controlv1.FeedbackThread{
		SchemaVersion: 1, Id: thread.ID, State: controlv1.FeedbackThreadState(thread.State),
		Scope: feedbackScope(thread), Report: feedbackReport(thread),
		Element: element, Evidence: evidence, CheckoutAtReport: marker,
	}, nil
}

func feedbackThreadSummary(thread controlstate.FeedbackThread) (controlv1.FeedbackThreadSummary, error) {
	var element controlv1.FeedbackElementSummary
	if err := json.Unmarshal(thread.Element, &element); err != nil {
		return controlv1.FeedbackThreadSummary{}, fmt.Errorf("decode stored feedback element: %w", err)
	}
	return controlv1.FeedbackThreadSummary{
		Id: thread.ID, State: controlv1.FeedbackThreadState(thread.State),
		Scope: feedbackScope(thread), Report: feedbackReport(thread), Element: element,
	}, nil
}

func feedbackThreadPageResponse(page controlstate.FeedbackThreadPage) (controlv1.FeedbackThreadPage, error) {
	result := controlv1.FeedbackThreadPage{
		Threads: make([]controlv1.FeedbackThreadSummary, 0, len(page.Threads)), EventCursor: int64(page.EventCursor),
	}
	for _, thread := range page.Threads {
		summary, err := feedbackThreadSummary(thread)
		if err != nil {
			return controlv1.FeedbackThreadPage{}, err
		}
		result.Threads = append(result.Threads, summary)
	}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	return result, nil
}

func feedbackEventResponse(event controlstate.FeedbackEvent) (controlv1.FeedbackEvent, error) {
	result := controlv1.FeedbackEvent{
		Cursor: int64(event.Cursor), FeedbackId: event.FeedbackID,
		Type: controlv1.FeedbackEventType(event.Type), Actor: controlv1.FeedbackEventActor(event.ActorKind), At: event.At,
	}
	if event.Text != "" {
		result.Text = &event.Text
	}
	if len(event.Evidence) != 0 {
		var evidence controlv1.FeedbackEvidence
		if err := json.Unmarshal(event.Evidence, &evidence); err != nil {
			return controlv1.FeedbackEvent{}, fmt.Errorf("decode stored follow-up evidence: %w", err)
		}
		result.Evidence = &evidence
	}
	if len(event.CheckoutMarker) != 0 {
		var marker controlv1.CheckoutMarker
		if err := json.Unmarshal(event.CheckoutMarker, &marker); err != nil {
			return controlv1.FeedbackEvent{}, fmt.Errorf("decode stored follow-up checkout marker: %w", err)
		}
		result.CheckoutMarker = &marker
	}
	return result, nil
}

func feedbackEventPageResponse(page controlstate.FeedbackEventPage) (controlv1.FeedbackEventPage, error) {
	result := controlv1.FeedbackEventPage{
		Events: make([]controlv1.FeedbackEvent, 0, len(page.Events)), EventCursor: int64(page.EventCursor),
	}
	for _, event := range page.Events {
		converted, err := feedbackEventResponse(event)
		if err != nil {
			return controlv1.FeedbackEventPage{}, err
		}
		result.Events = append(result.Events, converted)
	}
	if page.NextCursor != 0 {
		cursor := int64(page.NextCursor)
		result.NextCursor = &cursor
	}
	return result, nil
}
