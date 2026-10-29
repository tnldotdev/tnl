package control

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	policyfixture "github.com/tnldotdev/tnl/internal/testutil/visitorpolicy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherVisitorPolicyHTTPClientMaximum(t *testing.T) {
	body, _ := policyfixture.Maximum(t, time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC))
	if len(body.Policy.VerificationKeys) != 64 || len(body.Policy.WorkloadLeases) != 4096 || len(body.Policy.Ip.Prefixes) != 2048 {
		t.Fatal("maximum fixture lost a contracted collection limit")
	}
	body.AfterRevision = math.MaxInt64 - 256
	body.Policy.VisitorPolicyRevision = math.MaxInt64
	body.SnapshotRequired = false
	body.Revisions = make([]int64, 256)
	for i := range body.Revisions {
		body.Revisions[i] = body.AfterRevision + int64(i) + 1
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("maximum combined generated policy: %d bytes", len(raw))
	if len(raw) <= 512<<10 || len(raw) > maxVisitorPolicyResponseBytes {
		t.Fatal("combined fixture does not exercise the policy-specific byte budget")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/visitor-policy" || r.Header.Get("Authorization") != "Bearer fixture-run-secret" {
			t.Error("policy client lost operation or run authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{Resource: body.Policy.Resource, RunId: "srun_" + strings.Repeat("R", 22), RunNumber: math.MaxInt64}, "fixture-run-secret")
	if err != nil {
		t.Fatal("real policy client rejected the maximum combined response", err)
	}
	if !reflect.DeepEqual(result, body) {
		t.Fatal("policy client dropped fields or truncated the snapshot")
	}
	if _, err := visitorlease.Decode(result); err != nil {
		t.Fatal("maximum combined response did not reach local policy decoding", err)
	}
}

func TestPublisherVisitorPolicyHTTPClientResponseBudgetStaysLocal(t *testing.T) {
	for _, tc := range []struct {
		name          string
		size          int
		policy, valid bool
	}{
		{"policy at budget", maxVisitorPolicyResponseBytes, true, true},
		{"policy above budget", maxVisitorPolicyResponseBytes + 1, true, false},
		{"unrelated operation retains one MiB", maxResponseBytes + 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{}` + strings.Repeat(" ", tc.size-2)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(payload)) }))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.policy {
				_, err = client.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{}, "fixture-run-secret")
			} else {
				_, err = client.Discovery(t.Context())
			}
			if tc.valid {
				if err != nil {
					t.Fatal("policy exactly at byte limit was rejected", err)
				}
				return
			}
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("oversized response lost its owned invalid-response classification")
			}
		})
	}
}

func TestPublisherVisitorPolicyHTTPClientRetainsStrictDecoding(t *testing.T) {
	for _, payload := range []string{`{"private-response-body":true}`, `{} {}`, `null`, ``} {
		t.Run(payload, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(payload)) }))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{}, "fixture-run-secret")
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("invalid policy response escaped strict shared decoding")
			}
			_, definition, _ := failure.Describe(err)
			if strings.Contains(definition.Message, "private-response-body") {
				t.Fatal("raw response reached public diagnostics")
			}
		})
	}
}
