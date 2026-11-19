//go:build !js || !wasm

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ serviceFeedbackControl = (*Native)(nil)

type feedbackForwardingControl struct {
	*privateScopeControl
	ctx                     context.Context
	service, run, operation string
	number                  int64
	token                   credentials.ServiceRunToken
	body                    any
	calls                   int
	err                     error
	preview                 controlv1.Preview
	decision                controlv1.FeedbackAuthorization
}

func (c *feedbackForwardingControl) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	c.ctx, c.service, c.run, c.number, c.token, c.body = ctx, service, run, number, token, nil
	c.calls++
	return c.preview, c.err
}
func (c *feedbackForwardingControl) AuthorizeReviewerFeedback(ctx context.Context, service, run string, body controlv1.AuthorizeReviewerFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error) {
	c.ctx, c.service, c.run, c.number, c.token, c.body = ctx, service, run, body.RunNumber, token, body
	c.operation = string(body.Operation)
	c.calls++
	return c.decision, c.err
}
func TestServiceFeedbackForwardingRetainsSelectedRunCredentialAndBody(t *testing.T) {
	native, scope := privateScopeFixture(t)
	scope.service.Protocol = controlv1.ServiceProtocolHTTP
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	service, other := native.selectedServiceID, id(opaqueid.ServicePrefix)
	run, preview := id(opaqueid.ServiceRunPrefix), id(opaqueid.PreviewPrefix)
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	const number int64 = 7
	body := controlv1.AuthorizeReviewerFeedbackRequest{RunNumber: number, PreviewId: preview, Operation: "report", Access: controlv1.FeedbackReviewerAccess{BrowserCookieSecret: new("original-browser-cookie"), SourceIp: new("192.0.2.8"), VisitAllowed: true}}
	decision := controlv1.FeedbackAuthorization{PreviewId: preview, ServiceId: service, ServiceRunId: run, RunNumber: number, Operation: "report", ExpiresAt: time.Now().Add(time.Second)}
	previewResult := controlv1.Preview{Id: preview, SchemaVersion: 1, TeamId: scope.service.TeamId, ServiceIds: []string{service}}
	for _, test := range []struct {
		name           string
		body, response any
		call           func(context.Context, *Native, string) (any, error)
	}{
		{"preview", nil, previewResult, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.CreateServiceRunPreview(ctx, selected, run, number, token)
		}},
		{"authorization", body, decision, func(ctx context.Context, n *Native, selected string) (any, error) {
			return n.AuthorizeReviewerFeedback(ctx, selected, run, body, token)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker, err := native.Fork()
			if err != nil {
				t.Fatal(err)
			}
			control := &feedbackForwardingControl{privateScopeControl: scope, preview: previewResult, decision: decision}
			worker.NativeControl = NativeControl{Services: control}
			encode := func(value any) []byte {
				t.Helper()
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			expectedBody, expectedResponse := encode(test.body), encode(test.response)
			response, err := test.call(t.Context(), worker, service)
			if err != nil || control.calls != 1 || control.ctx != t.Context() || control.service != service || control.run != run || control.number != number || control.token != token ||
				!bytes.Equal(encode(control.body), expectedBody) || !bytes.Equal(encode(test.body), expectedBody) || !bytes.Equal(encode(response), expectedResponse) {
				t.Fatal("forwarding changed context, scope, credential, body or response", err)
			}
			for _, n := range []*Native{worker, func() *Native { n := *worker; n.selectedServiceID = ""; return &n }(), nil, func() *Native { n := *worker; n.Services = nil; return &n }()} {
				selected := service
				if n == worker {
					selected = other
				}
				if _, err := test.call(t.Context(), n, selected); !errors.Is(err, ErrScope) || control.calls != 1 {
					t.Fatal("feedback escaped selected capability", err)
				}
			}
			failed := errors.New("feedback backend failed")
			control.err = failed
			if _, err := test.call(t.Context(), worker, service); !errors.Is(err, failed) || control.calls != 2 {
				t.Fatal("backend failure lost", err)
			}
		})
	}
}
