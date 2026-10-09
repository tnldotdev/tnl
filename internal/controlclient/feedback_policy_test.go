package controlclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestFeedbackSignInProblemPreservesDistinctCause(t *testing.T) {
	payload, err := json.Marshal(controlv1.Problem{Code: controlv1.FeedbackSignInRequired, Title: "sign in to leave feedback", Status: 401})
	if err != nil {
		t.Fatal(err)
	}
	err = responseError(http.StatusUnauthorized, nil, payload)
	var problem *ProblemError
	if !errors.Is(err, ErrFeedbackSignInRequired) || errors.Is(err, ErrUnauthenticated) || !errors.As(err, &problem) || problem.Status != 401 {
		t.Fatalf("feedback problem cause=%v", err)
	}
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.FeedbackSignInRequired {
		t.Fatalf("reason=%s", reason)
	}
}

func TestFeedbackAccessResponsesRequireExplicitBoolean(t *testing.T) {
	for _, test := range []struct {
		name, payload   string
		valid, required bool
	}{
		{"true", `{"require_sign_in":true}`, true, true},
		{"false", `{"require_sign_in":false}`, true, false},
		{"missing", `{}`, false, false},
		{"null field", `{"require_sign_in":null}`, false, false},
		{"wrong type", `{"require_sign_in":"false"}`, false, false},
		{"unknown field", `{"require_sign_in":false,"other":true}`, false, false},
		{"null body", `null`, false, false},
		{"trailing JSON", `{"require_sign_in":false} {}`, false, false},
		{"over bound", `{"require_sign_in":false}` + strings.Repeat(" ", maxResponseBytes), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &responseBody{Reader: strings.NewReader(test.payload)}
			client, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/publish-runs/pr_test/feedback/access" || r.Header.Get("Authorization") != "Bearer publish-run-token" {
					t.Errorf("feedback access request = %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}, "")
			if err != nil {
				t.Fatal(err)
			}
			access, err := client.GetFeedbackAccess(t.Context(), "pr_test", controlv1.FeedbackAccessRequest{PreviewId: "pv_test", PublishRunNumber: 1, Access: controlv1.FeedbackReviewerAccess{AllowedIp: true}}, credentials.PublishRunToken("publish-run-token"))
			if !body.closed {
				t.Fatal("feedback access response body was not closed")
			}
			if test.valid {
				if err != nil || access.RequireSignIn != test.required {
					t.Fatalf("feedback access=%+v, %v", access, err)
				}
			} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatalf("invalid feedback access accepted: access=%+v err=%v reason=%s", access, err, reason)
			}
		})
	}
}
