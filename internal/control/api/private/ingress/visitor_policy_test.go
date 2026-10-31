package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ingressPolicyStoreFixture struct {
	Store
	read func(controlstate.IngressLeaseIdentity, visitorscope.Scope, string, int64, int64, int64, time.Time) (controlv1.VisitorPolicyUpdate, error)
}

func (s ingressPolicyStoreFixture) ReadIngressVisitorPolicy(_ context.Context, owner controlstate.IngressLeaseIdentity, scope visitorscope.Scope, run string, number, revision, after int64, now time.Time) (controlv1.VisitorPolicyUpdate, error) {
	return s.read(owner, scope, run, number, revision, after, now)
}

func TestIngressVisitorPolicyContractsMatchDirectAndHTTP(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	body := ingressv1.IngressVisitorPolicyRequest{IngressRunId: "ingress-process", IngressLeaseRevision: 3,
		Resource:     controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)},
		PublishRunId: "pr_" + strings.Repeat("B", 22), PublishRunNumber: 5, PolicyRevision: 7, AfterRevision: 11}
	want := controlv1.VisitorPolicyUpdate{AfterRevision: 11, Revisions: []int64{}, Policy: controlv1.VisitorPolicySnapshot{
		Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", Enabled: true,
		VisitorPolicyRevision: 11, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
		VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: bytes.Repeat([]byte{1}, 32)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}
	for _, test := range []struct {
		name   string
		change func(*ingressv1.IngressVisitorPolicyRequest)
		fail   error
		status int
		code   string
	}{
		{name: "prepared", status: http.StatusOK},
		{name: "stale projection", fail: controlstate.ErrVisitorPolicy, status: http.StatusConflict, code: "visitor_policy_stale"},
		{name: "stale process", fail: controlstate.ErrIngressLeaseStale, status: http.StatusConflict, code: "ingress_lease_stale"},
		{name: "wrong resource kind", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.Resource.Kind = "service" }, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "noncanonical resource", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.Resource.Id = "public_url_session" }, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "missing run", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.PublishRunId = "" }, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "missing number", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.PublishRunNumber = 0 }, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "missing projection revision", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.PolicyRevision = 0 }, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "negative visitor revision", change: func(b *ingressv1.IngressVisitorPolicyRequest) { b.AfterRevision = -1 }, status: http.StatusBadRequest, code: "invalid_request"},
	} {
		for _, transport := range []string{"direct", "HTTP"} {
			t.Run(test.name+"/"+transport, func(t *testing.T) {
				calls := 0
				store := ingressPolicyStoreFixture{read: func(owner controlstate.IngressLeaseIdentity, scope visitorscope.Scope, run string, number, revision, after int64, at time.Time) (controlv1.VisitorPolicyUpdate, error) {
					calls++
					if owner != (controlstate.IngressLeaseIdentity{IngressID: "ingress", IngressRunID: body.IngressRunId, IngressLeaseRevision: uint64(body.IngressLeaseRevision)}) ||
						scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: body.Resource.Id}) || run != body.PublishRunId || number != body.PublishRunNumber || revision != body.PolicyRevision || after != body.AfterRevision || !at.Equal(now) {
						t.Error("policy request lost its exact resource/run/process/projection binding")
					}
					return want, test.fail
				}}
				request := body
				if test.change != nil {
					test.change(&request)
				}
				status, code := http.StatusOK, ""
				var got controlv1.VisitorPolicyUpdate
				if transport == "direct" {
					client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }, Report: func(error) {}})
					if err != nil {
						t.Fatal(err)
					}
					got, err = client.ReadIngressVisitorPolicy(t.Context(), "ingress", request)
					if err != nil {
						var problem *serviceapi.ProblemError
						if !errors.As(err, &problem) {
							t.Fatal("unclassified direct error", err)
						}
						status, code = problem.Status, problem.Code
					}
				} else {
					wire := serveIngressJSON(t, testIngressHandler(t, store, now, nil), http.MethodPost, "/internal/v1/ingresses/ingress/visitor-policy", request)
					response, err := ingressv1.ParseReadIngressVisitorPolicyResponse(wire.Result())
					if err != nil {
						t.Fatal(err)
					}
					status = response.StatusCode()
					if response.JSON200 != nil {
						got = *response.JSON200
					} else if response.ApplicationproblemJSONDefault != nil {
						code = string(response.ApplicationproblemJSONDefault.Code)
					}
				}
				if status != test.status || code != test.code || test.change == nil && calls != 1 || test.change != nil && calls != 0 {
					t.Fatal("policy response classification or validation changed", status, code, calls)
				}
				if status == http.StatusOK && !reflect.DeepEqual(got, want) {
					t.Fatal("policy response changed its canonical wire shape")
				}
			})
		}
	}
}
