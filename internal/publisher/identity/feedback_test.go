package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ serviceFeedbackControl = (*Native)(nil)

type feedbackForwardingControl struct {
	*privateScopeControl
	ctx                                    context.Context
	operation, service, run, key, feedback string
	number                                 int64
	token                                  credentials.ServiceRunToken
	body                                   any
	calls                                  int
	err                                    error
	preview                                controlv1.Preview
	thread                                 controlv1.FeedbackThread
	page                                   controlv1.FeedbackThreadPage
	event                                  controlv1.FeedbackEvent
	events                                 controlv1.FeedbackEventPage
}

func (c *feedbackForwardingControl) capture(ctx context.Context, operation, service, run, key, feedback string, number int64, token credentials.ServiceRunToken, body any) {
	c.ctx, c.operation, c.service, c.run, c.key, c.feedback = ctx, operation, service, run, key, feedback
	c.number, c.token, c.body = number, token, body
	c.calls++
}

func (c *feedbackForwardingControl) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	c.capture(ctx, "preview", service, run, "", "", number, token, nil)
	return c.preview, c.err
}

func (c *feedbackForwardingControl) CreateFeedbackReport(ctx context.Context, service, run, key string, body controlv1.CreateFeedbackReportRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThread, error) {
	c.capture(ctx, "report", service, run, key, "", body.RunNumber, token, body)
	return c.thread, c.err
}

func (c *feedbackForwardingControl) ListPreviewPageFeedback(ctx context.Context, service, run string, body controlv1.PreviewPageFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThreadPage, error) {
	c.capture(ctx, "page", service, run, "", "", body.RunNumber, token, body)
	return c.page, c.err
}

func (c *feedbackForwardingControl) AppendReviewerFeedbackEvent(ctx context.Context, service, run, feedback, key string, body controlv1.AppendReviewerFeedbackEventRequest, token credentials.ServiceRunToken) (controlv1.FeedbackEvent, error) {
	c.capture(ctx, "append", service, run, key, feedback, body.RunNumber, token, body)
	return c.event, c.err
}

func (c *feedbackForwardingControl) GetReviewerFeedbackThread(ctx context.Context, service, run, feedback string, body controlv1.ReviewerFeedbackReadRequest, token credentials.ServiceRunToken) (controlv1.FeedbackThread, error) {
	c.capture(ctx, "thread", service, run, "", feedback, body.RunNumber, token, body)
	return c.thread, c.err
}

func (c *feedbackForwardingControl) ListReviewerFeedbackEvents(ctx context.Context, service, run, feedback string, body controlv1.ReviewerFeedbackReadRequest, token credentials.ServiceRunToken) (controlv1.FeedbackEventPage, error) {
	c.capture(ctx, "events", service, run, "", feedback, body.RunNumber, token, body)
	return c.events, c.err
}

func TestServiceFeedbackForwardingRetainsSelectedRunCredentialAndBody(t *testing.T) {
	native, scope := privateScopeFixture(t)
	scope.service.Protocol = controlv1.ServiceProtocolHTTP
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	service, other := native.selectedServiceID, id(opaqueid.ServicePrefix)
	run, preview, feedback := id(opaqueid.ServiceRunPrefix), id(opaqueid.PreviewPrefix), id(opaqueid.FeedbackPrefix)
	reportKey, eventKey, share := id(opaqueid.IdempotencyPrefix), id(opaqueid.IdempotencyPrefix), id(opaqueid.SharePrefix)
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	const number int64 = 7
	access := controlv1.FeedbackReviewerAccess{BrowserCookieSecret: new("original-browser-cookie"), CookieSecret: new("original-share-cookie"),
		ShareId: &share, ShareSecret: new("original-share-secret"), SourceIp: new("192.0.2.8"), VisitAllowed: true}
	evidence := controlv1.FeedbackEvidence{SchemaVersion: 1,
		Element: &controlv1.FeedbackElement{Html: new("<button>save</button>"), Label: new("save"), Role: new("button"), TestId: new("save-button")}}
	source := controlv1.SourceState{SchemaVersion: 1, HeadCommit: strings.Repeat("a", 40), Branch: "topic", ProjectPath: "apps/web", Complete: true,
		ChangedFiles: []controlv1.SourceFileState{}}
	report := controlv1.CreateFeedbackReportRequest{RunNumber: number, PreviewId: preview, PagePath: "/settings", PageTitle: new("settings"),
		Service: scope.service.Name, Access: access, Evidence: evidence, SourceAtReport: source}
	report.Report.Text = "original report"
	page := controlv1.PreviewPageFeedbackRequest{RunNumber: number, PreviewId: preview, Access: access,
		Cursor: &feedback, PagePath: new("/settings"), State: new(controlv1.Open)}
	appendEvent := controlv1.AppendReviewerFeedbackEventRequest{RunNumber: number, Access: access, Evidence: &evidence, SourceState: &source,
		Type: controlv1.ReviewerFeedbackInputReply, Text: new("original reply")}
	read := controlv1.ReviewerFeedbackReadRequest{RunNumber: number, PreviewId: preview, Access: access, AfterCursor: new(int64(23))}
	now := time.Now().UTC()
	previewResult := controlv1.Preview{Id: preview, SchemaVersion: 1, TeamId: scope.service.TeamId, ServiceIds: []string{service},
		TeamAccessEnabled: new(true), CreatedAt: now}
	threadResult := controlv1.FeedbackThread{Id: feedback, SchemaVersion: 1, State: controlv1.Open, MessageCount: 2, LatestEventCursor: 29,
		Report: controlv1.FeedbackReport{Text: "accepted report", CreatedAt: now}, Evidence: evidence, SourceAtReport: source,
		Scope: controlv1.FeedbackScope{PreviewId: preview, ServiceId: service, ServiceRunId: run, RunNumber: number,
			Service: scope.service.Name, PagePath: "/settings", PageTitle: new("settings")}}
	pageResult := controlv1.FeedbackThreadPage{SchemaVersion: 1, EventCursor: 29, NextCursor: &feedback,
		Threads: []controlv1.FeedbackThreadSummary{{Id: feedback, SchemaVersion: 1, State: controlv1.Open, Scope: threadResult.Scope,
			Report: threadResult.Report, MessageCount: 2, LatestEventCursor: 29}}}
	eventResult := controlv1.FeedbackEvent{FeedbackId: feedback, SchemaVersion: 1, Cursor: 31, At: now, Actor: controlv1.Reviewer,
		Type: "reply", Text: new("accepted reply"), Evidence: &evidence, SourceState: &source}
	eventsResult := controlv1.FeedbackEventPage{SchemaVersion: 1, EventCursor: 31, NextCursor: new(int64(32)), Events: []controlv1.FeedbackEvent{eventResult}}
	for _, test := range []struct {
		name, key, feedback string
		body, response      any
		call                func(context.Context, *Native, string) (any, error)
	}{
		{"preview", "", "", nil, previewResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.CreateServiceRunPreview(ctx, selected, run, number, token)
		}},
		{"report", reportKey, "", report, threadResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.CreateFeedbackReport(ctx, selected, run, reportKey, report, token)
		}},
		{"page", "", "", page, pageResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.ListPreviewPageFeedback(ctx, selected, run, page, token)
		}},
		{"append", eventKey, feedback, appendEvent, eventResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.AppendReviewerFeedbackEvent(ctx, selected, run, feedback, eventKey, appendEvent, token)
		}},
		{"thread", "", feedback, read, threadResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.GetReviewerFeedbackThread(ctx, selected, run, feedback, read, token)
		}},
		{"events", "", feedback, read, eventsResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.ListReviewerFeedbackEvents(ctx, selected, run, feedback, read, token)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker, err := native.Fork()
			if err != nil {
				t.Fatal(err)
			}
			control := &feedbackForwardingControl{privateScopeControl: scope, preview: previewResult, thread: threadResult,
				page: pageResult, event: eventResult, events: eventsResult}
			worker.NativeControl = NativeControl{Services: control}
			encode := func(value any) []byte {
				t.Helper()
				document, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return document
			}
			expectedBody, expectedResponse := encode(test.body), encode(test.response)
			response, err := test.call(t.Context(), worker, service)
			if err != nil || control.calls != 1 || control.ctx != t.Context() || control.operation != test.name ||
				control.service != service || control.run != run || control.number != number || control.token != token ||
				control.key != test.key || control.feedback != test.feedback || !bytes.Equal(encode(control.body), expectedBody) ||
				!bytes.Equal(encode(test.body), expectedBody) || !bytes.Equal(encode(response), expectedResponse) {
				t.Fatal("feedback forwarding changed the original context, service/run, key, feedback ID, credential, body, or response", err)
			}
			if _, err := test.call(t.Context(), worker, other); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("feedback forwarding escaped its selected service", err)
			}
			unselected := *worker
			unselected.selectedServiceID = ""
			if _, err := test.call(t.Context(), &unselected, service); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("unselected native forwarded feedback", err)
			}
			if _, err := test.call(t.Context(), nil, service); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("nil native forwarded feedback", err)
			}
			missing := *worker
			missing.Services = nil
			if _, err := test.call(t.Context(), &missing, service); !errors.Is(err, ErrScope) || control.calls != 1 {
				t.Fatal("missing service capability fell back to a retired control client", err)
			}
			failed := errors.New("feedback backend failed")
			control.err = failed
			if _, err := test.call(t.Context(), worker, service); !errors.Is(err, failed) || control.calls != 2 {
				t.Fatal("feedback forwarding lost its selected backend failure", err)
			}
		})
	}
}
