package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type nativeAuditFixture struct {
	NativeControl
	calls int
	token credentials.PublishRunToken
}

func (c *nativeAuditFixture) ReportPublisherServiceObservations(_ context.Context, _ string, _ uint64, token credentials.PublishRunToken, _ serviceaudit.Batch) error {
	c.calls++
	c.token = token
	return nil
}
func TestConnectorAuditForwardingRetainsSelectedServiceAndRunCredential(t *testing.T) {
	c := &nativeAuditFixture{}
	n := &Native{NativeControl: c, publicURL: controlv1.PublicURL{Id: "url_0123456789ABCDEFGHIJKL"}}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: n.publicURL.Id, ServiceKind: "public_url", RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, EventType: "http.decision", VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", OccurredAt: time.Now(), Outcome: "allowed"}
	if err := n.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "run-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); err != nil || c.calls != 1 || c.token != "run-token" {
		t.Fatal("native lost audit capability or credential", err)
	}
	o.ServiceID = "url_ABCDEFGHIJKL0123456789"
	if err := n.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "run-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); !errors.Is(err, ErrScope) || c.calls != 1 {
		t.Fatal("audit escaped selected native service", err)
	}
}
