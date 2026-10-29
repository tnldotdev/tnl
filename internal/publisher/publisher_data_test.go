package publisher

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestServiceHTTPAuthorizationObservesLocalDecisionAndPreservesFailure(t *testing.T) {
	for _, scenario := range []string{"admitted", "denied", "failed"} {
		t.Run(scenario, func(t *testing.T) {
			m := observability.New("publisher")
			defer m.Shutdown(context.Background())
			ctx := observability.WithFields(observability.WithMetrics(t.Context(), m), observability.Fields{ServiceProtocol: observability.ProtocolHTTP})
			policy, update, token := httpPermissionFixture(t, false)
			r := permissionRequest().WithContext(ctx)
			r.Header.Set(visitorTokenHeader, token.Reveal())
			if scenario == "denied" {
				r.Header.Set(visitorTokenHeader, "invalid")
			}
			if scenario == "failed" {
				update.View = update.View.WithVerificationKeys(map[string]ed25519.PublicKey{"new": ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32))).Public().(ed25519.PublicKey)})
				update.KeyRevision++
				if err := policy.Apply(policy.Begin(), update); err != nil {
					t.Fatal(err)
				}
			}
			_, guard, _, err := authorizeHTTPRequest(httptest.NewRecorder(), r, policy, nil)
			if (err == nil) != (scenario == "admitted") {
				t.Fatal("authorization result changed", err)
			}
			if guard != nil {
				guard.finish()
			}
			scrape := httptest.NewRecorder()
			m.Handler().ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
			if !strings.Contains(scrape.Body.String(), `tnl_state="`+scenario+`"`) {
				t.Fatal(scrape.Body.String())
			}
			families, err := m.Gather()
			if err != nil {
				t.Fatal(err)
			}
			outcome := map[string]string{"admitted": "success", "denied": "denied", "failed": "error"}[scenario]
			var measured uint64
			for _, family := range families {
				if family.GetName() != "tnl_publisher_operation_duration_seconds" {
					continue
				}
				for _, point := range family.Metric {
					labels := map[string]string{}
					for _, label := range point.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["tnl_operation"] == "visitor_authorization" && labels["tnl_outcome"] == outcome && labels["tnl_service_protocol"] == "http" {
						measured += point.GetHistogram().GetSampleCount()
					}
				}
			}
			if measured != 1 {
				t.Fatal("local authorization timing lost its result", outcome, measured)
			}
		})
	}
}
