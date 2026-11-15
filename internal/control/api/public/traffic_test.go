package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceRunTrafficResponseUsesResolvedPeriod(t *testing.T) {
	l := trafficlimits.Default()
	l.RatePer = 2_000_000_000
	l.TotalConnections = 10
	r := trafficLimitsResponse(l)
	if r == nil || r.RatePerNs != 2_000_000_000 || r.TotalConnections == nil || *r.TotalConnections != 10 || r.TotalUploadBytes != nil {
		t.Fatalf("traffic wire limits: %+v", r)
	}
}

func TestServiceRunTrafficInputBoundary(t *testing.T) {
	for _, traffic := range []string{
		`null`, `{"connections":null}`, `{"rate_per":null}`, `{"total_connections":null}`,
		`{"connections":0}`, `{"rate_per":"1ns"}`, `{"upload_bytes":1}`, `{"unknown":1}`,
	} {
		t.Run(traffic, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"protocol":"tcp","trust_revision":"1","traffic":`+traffic+`}`))
			(&handler{}).PrepareServiceRun(w, r, "service", controlv1.PrepareServiceRunParams{})
			if w.Code != http.StatusBadRequest {
				t.Fatal("invalid traffic reached publisher authority", w.Code, w.Body.String())
			}
		})
	}
}
