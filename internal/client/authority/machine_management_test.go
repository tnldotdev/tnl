package authority

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestWorkloadApprovalRequestsUseExactIntentAndHumanCredential(t *testing.T) {
	var methods []string
	c, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		if r.URL.Path != "/v1/teams/team/workload-approvals/intent-1" || r.Header.Get("Authorization") != "Bearer human-token" {
			t.Fatal("lost explicit approval intent or control session")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("unbounded approval request")
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{"code":"not_found","title":"missing"}`))}, nil
	})}, "human-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetWorkloadApproval(t.Context(), "team", "intent-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := c.ApproveWorkload(t.Context(), "team", "intent-1", authorityv1.WorkloadApprovalRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET,PUT" {
		t.Fatal(methods)
	}
}

func TestWorkloadApprovalResponsesRequireReceipt(t *testing.T) {
	for _, payload := range []string{"", "null", "{}", `{"intent_key":"intent","request":null,"machine":{},"selection":{},"created_at":"2026-11-12T00:00:00Z"}`} {
		t.Run(payload, func(t *testing.T) {
			c, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload))}, nil
			})}, "human-token")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetWorkloadApproval(t.Context(), "team", "intent")
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("accepted empty or null receipt", err)
			}
		})
	}
}
