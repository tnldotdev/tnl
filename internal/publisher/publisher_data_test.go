package publisher

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type measuredHTTPAuthority struct {
	ManagedHTTPControl
	decisions []controlv1.ServiceClientCertificateDecision
	cause     error
	calls     int
}

func (c *measuredHTTPAuthority) AuthorizeManagedHTTPVisitor(context.Context, string, string, credentials.PublishRunToken, controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c.calls++
	if c.cause != nil {
		return controlv1.ServiceClientCertificateDecision{}, c.cause
	}
	decision := c.decisions[min(c.calls-1, len(c.decisions)-1)]
	return decision, nil
}

func TestManagedHTTPAuthorizationObservesPendingDenialAndPreservesFailure(t *testing.T) {
	for _, scenario := range []string{"pending", "denied", "infrastructure"} {
		t.Run(scenario, func(t *testing.T) {
			m := observability.New("publisher")
			defer m.Shutdown(context.Background())
			ctx := observability.WithMetrics(t.Context(), m)
			cause := errors.New("secret authority response")
			control := &measuredHTTPAuthority{decisions: []controlv1.ServiceClientCertificateDecision{{}}}
			switch scenario {
			case "pending":
				control.decisions = []controlv1.ServiceClientCertificateDecision{{Allowed: true}, {Allowed: true, Admitted: true, ValidUntil: time.Now().Add(time.Minute)}}
			case "infrastructure":
				control.cause = cause
			}
			decision, err := (ManagedHTTP{Control: control}).authorize(ctx, controlv1.ManagedHTTPCredential{Kind: "none"})
			if scenario == "infrastructure" && !errors.Is(err, cause) {
				t.Fatal("lost infrastructure cause", err)
			}
			if scenario != "infrastructure" && err != nil {
				t.Fatal(err)
			}
			if scenario == "pending" && (!decision.Admitted || control.calls != 2) {
				t.Fatal("pending admission changed", decision, control.calls)
			}
			scrape := httptest.NewRecorder()
			m.Handler().ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
			text := scrape.Body.String()
			state := scenario
			if scenario == "infrastructure" {
				state = "failed"
			}
			if !strings.Contains(text, `tnl_state="`+state+`"`) || strings.Contains(text, "secret") {
				t.Fatal(text)
			}
			if scenario == "pending" && !strings.Contains(text, `tnl_state="admitted"`) {
				t.Fatal(text)
			}
		})
	}
}
