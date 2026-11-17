package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPDemoPreviewBindsExactRunBeforeFeedbackAndRecoversOnRetry(t *testing.T) {
	const previewID = "pv_0123456789abcdefghijkl"
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"}
	runID, number, runToken := "srun_0123456789abcdefghijkl", int64(7), credentials.ServiceRunToken("run-secret")
	policy := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
	lost := errors.New("preview reply lost after creation")
	ctx := t.Context()
	calls := 0
	feedback := &feedbackControlStub{preview: func(actualContext context.Context, service, run string, actualNumber int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
		calls++
		if actualContext != ctx || service != scope.ID || run != runID || actualNumber != number || token != runToken {
			t.Error("demo preview creation escaped its exact service run")
		}
		if calls == 1 {
			return controlv1.Preview{}, lost
		}
		// the control operation is keyed by the same service/run, not a client
		// project or a newly generated idempotency key on each preparation.
		return controlv1.Preview{Id: previewID, SchemaVersion: 1, ServiceIds: []string{scope.ID}}, nil
	}}
	control := serviceBrowserControl{HTTPControl: feedback, origin: "https://control.example.test", policy: policy}
	facts := HTTP{Control: control, Subject: scope, RunID: runID, Number: number, Token: runToken,
		State: testFeedbackState(t),
		Demo:  true, Feedback: true, ProjectService: "demo", PreviewID: "pv_caller0123456789abcdef"}
	failed, closeHTTP, err := PrepareHTTP(ctx, facts)
	if !errors.Is(err, lost) || closeHTTP != nil || failed.browser != nil || failed.feedback != nil || policy.Calls.Load() != 0 {
		t.Fatal("failed demo preview started HTTP work or lost the creation failure", err)
	}
	for range 2 {
		prepared, closeHTTP, err := PrepareHTTP(ctx, facts)
		if err != nil {
			t.Fatal(err)
		}
		if prepared.PreviewID != previewID || prepared.browser == nil || prepared.browser.PreviewID != previewID ||
			prepared.feedback == nil || prepared.feedback.previewID != previewID || !prepared.feedback.demo ||
			prepared.feedback.serviceID != scope.ID || prepared.feedback.runID != runID || prepared.feedback.number != number ||
			prepared.feedback.token != runToken || prepared.feedback.projectRoot != "" ||
			prepared.ResponseHooks.ModifyHTML == nil || prepared.ResponseHooks.ObserveStatus == nil {
			closeHTTP()
			t.Fatal("demo browser/feedback did not use the recovered run preview and direct run facts")
		}
		source, err := prepared.feedback.sourceState(ctx)
		if err != nil || source.SchemaVersion != 1 || source.Complete || source.ChangedFiles == nil || len(source.ChangedFiles) != 0 {
			closeHTTP()
			t.Fatal("demo source capture left its existing bounded mode", source, err)
		}
		closeHTTP()
	}
	if calls != 3 || facts.PreviewID != "pv_caller0123456789abcdef" {
		t.Fatal("demo preparation skipped recovery or mutated the caller's preview", calls)
	}
}

func TestServiceHTTPDemoPreviewRejectsInvalidIdentityAndMembershipBeforeStartup(t *testing.T) {
	const serviceID = "svc_0123456789abcdefghijkl"
	for _, test := range []struct {
		name    string
		preview controlv1.Preview
	}{
		{"missing ID", controlv1.Preview{SchemaVersion: 1, ServiceIds: []string{serviceID}}},
		{"wrong ID kind", controlv1.Preview{Id: serviceID, SchemaVersion: 1, ServiceIds: []string{serviceID}}},
		{"unsupported schema", controlv1.Preview{Id: "pv_0123456789abcdefghijkl", SchemaVersion: 2, ServiceIds: []string{serviceID}}},
		{"no membership", controlv1.Preview{Id: "pv_0123456789abcdefghijkl", SchemaVersion: 1}},
		{"wrong service", controlv1.Preview{Id: "pv_0123456789abcdefghijkl", SchemaVersion: 1, ServiceIds: []string{"svc_abcdefghijkl0123456789"}}},
		{"additional service", controlv1.Preview{Id: "pv_0123456789abcdefghijkl", SchemaVersion: 1, ServiceIds: []string{serviceID, "svc_abcdefghijkl0123456789"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
			calls := 0
			feedback := &feedbackControlStub{preview: func(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error) {
				calls++
				return test.preview, nil
			}}
			facts := HTTP{Control: serviceBrowserControl{HTTPControl: feedback, origin: "https://control.example.test", policy: policy},
				Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, RunID: "srun_0123456789abcdefghijkl",
				Number: 7, Token: "run-secret", Demo: true, Feedback: true, ProjectService: "demo", PreviewID: "pv_abcdefghijkl0123456789"}
			prepared, closeHTTP, err := PrepareHTTP(t.Context(), facts)
			if closeHTTP != nil {
				closeHTTP()
			}
			if reason, _ := failure.ReasonOf(err); reason != failure.ServerResponseInvalid || calls != 1 ||
				prepared.browser != nil || prepared.feedback != nil || closeHTTP != nil || policy.Calls.Load() != 0 {
				t.Fatal("invalid demo preview enabled HTTP work or fell back to the caller's preview", err, calls)
			}
		})
	}
}

func TestServiceHTTPConfiguredPreviewDoesNotAllocateADemoPreview(t *testing.T) {
	const previewID = "pv_0123456789abcdefghijkl"
	policy := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
	calls := 0
	feedback := &feedbackControlStub{preview: func(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error) {
		calls++
		return controlv1.Preview{}, errors.New("configured previews must not allocate a demo preview")
	}}
	facts := HTTP{Control: serviceBrowserControl{HTTPControl: feedback, origin: "https://control.example.test", policy: policy},
		State:   testFeedbackState(t),
		Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"}, RunID: "srun_0123456789abcdefghijkl",
		Number: 7, Token: "run-secret", Feedback: true, ProjectService: "web", ProjectRoot: t.TempDir(), PreviewID: previewID}
	prepared, closeHTTP, err := PrepareHTTP(t.Context(), facts)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHTTP()
	if calls != 0 || prepared.PreviewID != previewID || prepared.browser == nil || prepared.browser.PreviewID != previewID ||
		prepared.feedback == nil || prepared.feedback.previewID != previewID || prepared.feedback.demo ||
		prepared.feedback.projectRoot != facts.ProjectRoot {
		t.Fatal("ordinary configured feedback allocated or replaced its preview", calls)
	}
}
