package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestIngressServicesRestoredTypedProblemCorrelationAndDetails(t *testing.T) {
	now := time.Now().UTC()
	lease := controlstate.IngressLeaseIdentity{IngressID: "ingress-one", IngressRunID: "ir_" + strings.Repeat("a", 22), IngressLeaseRevision: 7}
	calls := 0
	store := &ingressStoreStub{readIngressServices: func(_ context.Context, got controlstate.IngressLeaseIdentity, at time.Time) (controlstate.IngressServices, error) {
		calls++
		if got != lease || !at.Equal(now) {
			t.Fatal("failed service snapshot changed its exact lease or observation time")
		}
		return controlstate.IngressServices{}, controlstate.ErrIngressLeaseStale
	}}
	body := ingressv1.IngressLeaseIdentity{IngressId: lease.IngressID, IngressRunId: lease.IngressRunID, IngressLeaseRevision: 7}
	server := httptest.NewServer(testIngressHandler(t, store, now, nil))
	t.Cleanup(server.Close)
	client, err := ingressv1.NewClientWithResponses(server.URL, ingressv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+testIngressClusterSecret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.ReadIngressServicesWithResponse(t.Context(), lease.IngressID, body)
	if err != nil || wire.StatusCode() != 409 || wire.ApplicationproblemJSONDefault == nil {
		t.Fatal("typed ingress stale-lease problem missing", err)
	}
	problem := wire.ApplicationproblemJSONDefault
	if problem.RequestId == "" || problem.Details == nil || wire.HTTPResponse.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatal("typed ingress problem lost correlation, details, or media type")
	}
	direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = direct.ReadIngressServices(t.Context(), lease.IngressID, body)
	var failure *serverhttp.ProblemError
	if !errors.As(err, &failure) || failure.Status != problem.Status || failure.Type != problem.Type ||
		failure.Title != problem.Title || failure.Code != string(problem.Code) || failure.Detail != problem.Detail || calls != 2 {
		t.Fatal("direct and HTTP stable problem fields or exact backend call counts diverged", err)
	}
}
