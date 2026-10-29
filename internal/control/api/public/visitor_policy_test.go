package public

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherPolicyStoreFixture struct {
	Store
	calls int
}

func (s *publisherPolicyStoreFixture) ReadPublisherVisitorPolicy(_ context.Context, _ visitorscope.Scope, _ string, _ int64, _ string, _ int64, _ time.Time) (controlv1.VisitorPolicyUpdate, error) {
	s.calls++
	return controlv1.VisitorPolicyUpdate{}, nil
}

func TestPublisherVisitorPolicyGeneratedMaximumRequest(t *testing.T) {
	store := &publisherPolicyStoreFixture{}
	server := httptest.NewServer(testHandler(t, Config{}, store, nil, nil))
	defer server.Close()
	client, err := controlv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body := controlv1.PublisherVisitorPolicyRequest{
		Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)},
		RunId:    strings.Repeat("\x01", 64), RunNumber: math.MaxInt64, AfterRevision: math.MaxInt64,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxPublisherVisitorPolicyRequestBytes {
		t.Fatal("generated maximum request exceeds its budget")
	}
	t.Logf("maximum generated request: %d bytes", len(raw))
	response, err := client.ReadPublisherVisitorPolicyWithResponse(t.Context(), body, func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture-run-secret")
		return nil
	})
	if err != nil || response.StatusCode() != http.StatusOK {
		t.Fatal("generated maximum policy request was rejected", err)
	}
	if store.calls != 1 {
		t.Fatal("handler did not fetch the policy exactly once")
	}
}

func TestPublisherVisitorPolicyRejectsInvalidBodiesBeforeBackend(t *testing.T) {
	base := `{"resource":{"kind":"public_url","id":"url_` + strings.Repeat("A", 22) + `"},"run_id":"run","run_number":1,"after_revision":0`
	empty := base + `}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid request", empty, true},
		{"null observations", base + `,"observed_allocations":null}`, false},
		{"retired observations", base + `,"observed_allocations":[]}`, false},
		{"at byte limit", empty + strings.Repeat(" ", maxPublisherVisitorPolicyRequestBytes-len(empty)), true},
		{"over byte limit", empty + strings.Repeat(" ", maxPublisherVisitorPolicyRequestBytes+1-len(empty)), false},
		{"unknown field", base + `,"private-request-body":true}`, false},
		{"trailing JSON", empty + ` {}`, false},
		{"malformed JSON", base + `,"observed_allocations":[}`, false},
		{"maximum Unicode run ID", strings.Replace(empty, `"run_id":"run"`, `"run_id":"`+strings.Repeat("界", 64)+`"`, 1), true},
		{"overlong run ID", strings.Replace(empty, `"run_id":"run"`, `"run_id":"`+strings.Repeat("界", 65)+`"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &publisherPolicyStoreFixture{}
			h := testHandler(t, Config{}, store, nil, nil)
			r := httptest.NewRequest("POST", "/v1/visitor-policy", bytes.NewBufferString(tc.body))
			r.Header.Set("Authorization", "Bearer fixture-run-secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if tc.valid {
				if w.Code != 200 || store.calls != 1 {
					t.Fatal("valid request was not accepted exactly once")
				}
				return
			}
			var problem controlv1.Problem
			if w.Code != 400 || store.calls != 0 || json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.Code != controlv1.InvalidRequest {
				t.Fatal("invalid policy request reached backend or lost its classification")
			}
			if strings.Contains(w.Body.String(), "private-request-body") {
				t.Fatal("request body leaked into diagnostics")
			}
		})
	}
}
