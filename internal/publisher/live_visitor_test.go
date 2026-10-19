package publisher

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type scopedHTTPDecision struct {
	shareHeaderDecisionClient
	t       *testing.T
	calls   int
	allowed bool
	runID   string
}

func (c *scopedHTTPDecision) AuthorizeHTTPVisitor(_ context.Context, run string, input controlv1.HTTPVisitorRequest, token credentials.PublishRunToken) (controlv1.HTTPVisitorResponse, error) {
	c.calls++
	if run != c.runID || token != "private-run-token" || input.SourceIp != "192.0.2.10" && input.SourceIp != "192.0.2.11" {
		c.t.Error("HTTP authorization lost trusted run, token, or source")
	}
	expires := time.Now().Add(time.Minute)
	return controlv1.HTTPVisitorResponse{VisitAllowed: c.allowed, ValidUntil: &expires}, nil
}

func TestHTTPDecisionCacheBindsRunSourceProofAndDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &scopedHTTPDecision{t: t, allowed: true, runID: "run-one"}
		access := &browserAccess{client: client, runID: client.runID, publicURLID: "url-one", version: 7, token: "private-run-token", decisions: &visitorDecisionCache[controlv1.HTTPVisitorResponse]{}}
		request := httptest.NewRequest("GET", "https://route.example/", nil)
		request.RemoteAddr = "203.0.113.99:1234"
		request.Header.Set("X-Forwarded-For", "203.0.113.100")
		visitor := &visitorSession{visitor: Visitor{Source: netip.MustParseAddrPort("192.0.2.10:1234")}}
		request = request.WithContext(context.WithValue(request.Context(), visitorSessionKey{}, visitor))
		for range 2 {
			if got, err := access.decision(request); err != nil || !got.VisitAllowed {
				t.Fatalf("HTTP decision: %+v, %v", got, err)
			}
		}
		if client.calls != 1 {
			t.Fatal("same HTTP proof did not share its decision")
		}
		visitor.visitor.Source = netip.MustParseAddrPort("192.0.2.11:1234")
		if _, err := access.decision(request); err != nil || client.calls != 2 {
			t.Fatalf("different source reused decision: %v, %d", err, client.calls)
		}
		client.runID, access.runID = "run-two", "run-two"
		if _, err := access.decision(request); err != nil || client.calls != 3 {
			t.Fatalf("different run reused decision: %v, %d", err, client.calls)
		}
		request.Header.Set(shareAccessHeaderName, "shr_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if _, err := access.decision(request); err != nil || client.calls != 4 {
			t.Fatalf("different proof reused decision: %v, %d", err, client.calls)
		}
		client.allowed = false
		time.Sleep(time.Minute)
		if got, err := access.decision(request); err != nil || got.VisitAllowed || client.calls != 5 {
			t.Fatalf("expired permission survived: %+v, %v, checks=%d", got, err, client.calls)
		}
	})
}
