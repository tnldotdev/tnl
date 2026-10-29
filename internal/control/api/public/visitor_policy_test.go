package public

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	policyfixture "github.com/tnldotdev/tnl/internal/testutil/visitorpolicy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherPolicyStoreFixture struct {
	Store
	calls    int
	observed []string
}

func (s *publisherPolicyStoreFixture) ReadPublisherVisitorPolicy(_ context.Context, _ visitorscope.Scope, _ string, _ int64, _ string, _ int64, observed []string, _ time.Time) (controlv1.VisitorPolicyUpdate, error) {
	s.calls++
	s.observed = observed
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
		ObservedAllocations: policyfixture.ObservationIDs(),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 64<<10 {
		t.Fatal("maximum observation fixture does not cross the old small limits")
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
	if store.calls != 1 || !reflect.DeepEqual(store.observed, body.ObservedAllocations) {
		t.Fatal("handler dropped or split maximum observations")
	}
}

func TestPublisherVisitorPolicyRejectsInvalidBodiesBeforeBackend(t *testing.T) {
	base := `{"resource":{"kind":"public_url","id":"url_` + strings.Repeat("A", 22) + `"},"run_id":"run","run_number":1,"after_revision":0`
	empty := base + `,"observed_allocations":[]}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"missing observations", base + `}`, false},
		{"null observations", base + `,"observed_allocations":null}`, false},
		{"empty observations", base + `,"observed_allocations":[]}`, true},
		{"at byte limit", empty + strings.Repeat(" ", maxPublisherVisitorPolicyRequestBytes-len(empty)), true},
		{"over byte limit", empty + strings.Repeat(" ", maxPublisherVisitorPolicyRequestBytes+1-len(empty)), false},
		{"over item limit", func() string {
			ids := append(policyfixture.ObservationIDs(), "salloc_"+strings.Repeat("Z", 22))
			raw, _ := json.Marshal(ids)
			return base + `,"observed_allocations":` + string(raw) + `}`
		}(), false},
		{"invalid observation ID", base + `,"observed_allocations":["private-request-body"]}`, false},
		{"duplicate observations", base + `,"observed_allocations":["salloc_` + strings.Repeat("A", 22) + `","salloc_` + strings.Repeat("A", 22) + `"]}`, false},
		{"unknown field", base + `,"observed_allocations":[],"private-request-body":true}`, false},
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
					t.Fatal("empty observation list was not accepted exactly once")
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
