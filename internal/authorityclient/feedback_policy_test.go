package authorityclient

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestTeamFeedbackPolicyResponsesRequireExplicitBoolean(t *testing.T) {
	for _, operation := range []string{"get", "set true", "set false"} {
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
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				body := &responseBody{Reader: strings.NewReader(test.payload)}
				client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					method := http.MethodGet
					if operation != "get" {
						method = http.MethodPut
					}
					if r.Method != method || r.URL.Path != "/v1/teams/team_test/feedback-policy" || r.Header.Get("Authorization") != "Bearer test-access" {
						t.Errorf("policy request = %s %s", r.Method, r.URL)
					}
					return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
				})}, "test-access")
				if err != nil {
					t.Fatal(err)
				}
				requested := operation == "set true"
				valid := test.valid && (operation == "get" || test.required == requested)
				var policy authorityv1.TeamFeedbackPolicy
				if operation == "get" {
					policy, err = client.GetTeamFeedbackPolicy(t.Context(), "team_test")
				} else {
					policy, err = client.SetTeamFeedbackPolicy(t.Context(), "team_test", requested)
				}
				if !body.closed {
					t.Fatal("policy response body was not closed")
				}
				if valid {
					if err != nil || policy.RequireSignIn != test.required {
						t.Fatalf("policy=%+v, %v", policy, err)
					}
				} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
					t.Fatalf("invalid policy response accepted: policy=%+v err=%v reason=%s", policy, err, reason)
				}
			})
		}
	}
}
