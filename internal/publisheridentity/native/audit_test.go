package native

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
func TestNativeAuditForwardingRetainsSelectedServiceAndRunCredential(t *testing.T) {
	c := &nativeAuditFixture{}
	n := &Native{NativeControl: c, route: controlv1.PublicURL{Id: "url_0123456789ABCDEFGHIJKL"}}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: n.route.Id, ServiceKind: "public_url", RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, EventType: "http.decision", VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", OccurredAt: time.Now(), Outcome: "allowed"}
	if err := n.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "run-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); err != nil || c.calls != 1 || c.token != "run-token" {
		t.Fatal("native lost audit capability or credential", err)
	}
	o.ServiceID = "url_ABCDEFGHIJKL0123456789"
	if err := n.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "run-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); !errors.Is(err, ErrScope) || c.calls != 1 {
		t.Fatal("audit escaped selected native service", err)
	}
}
