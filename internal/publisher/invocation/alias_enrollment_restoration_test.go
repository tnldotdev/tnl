package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAliasPreparationRedeemsExactlyItsIssuedEnrollmentKey(t *testing.T) {
	f := newServiceSetupFixture(t, "review.member.example")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	issued, forwarded := "", []string{}
	// observe the existing fixture's actual response and request. it still
	// owns enrollment, key capture, signed assertion verification, and grants.
	transport := serviceSetupTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher-enrollments/redeem" {
			data, err := io.ReadAll(r.Body)
			err = errors.Join(err, r.Body.Close())
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			var body authorityv1.RedeemPublisherEnrollmentRequest
			if err := json.Unmarshal(data, &body); err != nil {
				return nil, err
			}
			if issued == "" || body.EnrollmentKey != issued || r.Header.Get("Authorization") != "" {
				t.Error("alias redemption changed its issued key or used a person token")
			}
			forwarded = append(forwarded, body.EnrollmentKey)
		}
		response, err := f.serve(r)
		if err != nil || r.Method != http.MethodPost || r.URL.Path != "/v1/publisher-enrollments" {
			return response, err
		}
		data, readErr := io.ReadAll(response.Body)
		readErr = errors.Join(readErr, response.Body.Close())
		if readErr != nil {
			return nil, readErr
		}
		response.Body = io.NopCloser(bytes.NewReader(data))
		var enrollment controlv1.PublisherEnrollment
		if err := json.Unmarshal(data, &enrollment); err != nil {
			return nil, err
		}
		if enrollment.Id != f.enrollment || enrollment.EnrollmentKey == "" {
			t.Error("alias fixture did not issue its actual enrollment")
		}
		issued = enrollment.EnrollmentKey
		return response, nil
	})
	client := &http.Client{Transport: transport}
	control, err := clientcontrol.New(f.services.authenticated.ServerEndpoint, client, "session")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.services.authenticated.ServerEndpoint, client, "session")
	if err != nil {
		t.Fatal(err)
	}
	f.services.routes, f.services.authenticated.Control, f.services.authenticated.Authority = control, control, authority
	project := t.TempDir()
	group := clientstate.IntegrationScope{PrimaryProjectRoot: project, Namespace: "member.example"}
	f.services.membershipID, f.services.namespace = serviceTestID(t, opaqueid.MembershipPrefix), group.Namespace
	f.parent = controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix), TeamId: f.saved.TeamId, DomainId: f.saved.DomainId,
		Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.member.example", Port: 443, Public: true}}
	tunnel, err := f.state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
		Server: control.ControlURL(), Project: project, Service: "web", ServiceID: f.parent.Id,
		Target: "http://127.0.0.1:3000", IntegrationScope: group})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if err := tunnel.Finish(cleanup, nil); err != nil {
			t.Error("finish alias entry service", err)
		}
	})
	if err := tunnel.SetProvisioning(ctx, 1); err != nil {
		t.Fatal(err)
	}
	selection, err := f.state.RegisterAlias(ctx, clientstate.AliasRegistration{
		Scope: clientstate.AliasScope{Server: control.ControlURL(), ProjectKey: project, TeamID: f.saved.TeamId,
			MembershipID: f.services.membershipID, Namespace: group.Namespace, Name: "review"},
		Hostname: f.saved.Endpoint.Hostname, Service: "web", TunnelID: tunnel.ID(), IntegrationScope: group})
	if err != nil {
		t.Fatal(err)
	}
	base := publisherservice.RunConfig{Control: control, Access: func(context.Context) (string, error) { return "parent-access", nil },
		ServiceID: f.parent.Id, Target: "http://127.0.0.1:3000", Metadata: publisheridentity.ServiceMetadata(f.parent)}
	worker := projectAliasPublisher(f.state, f.services, selection, tunnel.ID(), base,
		resolvedVisitorAccess{access: controlv1.Restricted}, nil)
	if _, err := worker.Prepare(ctx); !errors.Is(err, clientstate.ErrAliasReceiverUnavailable) || f.requests != 0 {
		t.Fatal("unready alias acquired enrollment authority", err)
	}
	if err := tunnel.SetReady(ctx, "https://"+f.parent.Endpoint.Hostname, 1); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		prepared, err := worker.Prepare(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if f.declaration.Http == nil || f.declaration.Http.Access == nil || f.declaration.Http.Access.Mode == nil ||
			*f.declaration.Http.Access.Mode != controlv1.Restricted || f.declaration.Http.Access.Ip != nil {
			t.Fatal("alias without an IP selection sent an invalid empty IP filter")
		}
		cfg := prepared.Config
		if cfg.ServiceID != f.saved.Id || cfg.PublisherIdentityID != f.identity.ClientId ||
			cfg.PublisherGrantID != f.identity.GrantId || cfg.PublisherKeyID != f.identity.KeyId {
			t.Fatal("alias preparation changed its actual exact-service grant")
		}
		access, err := cfg.Access(ctx)
		if err != nil {
			t.Fatal("alias signing exchange failed", err)
		}
		if _, err := cfg.Control.PrepareServiceRun(ctx, cfg.ServiceID, serviceTestID(t, opaqueid.IdempotencyPrefix),
			access, publisheridentity.ServiceDeclaration(prepared.Service)); !errors.Is(err, clientcontrol.ErrUnavailable) {
			t.Fatal("alias run lost its signed publisher authority", err)
		}
	}
	if issued == "" || len(forwarded) != 1 || forwarded[0] != issued ||
		f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || f.runs != 2 {
		t.Fatal("alias preparation did not forward one exact issued enrollment through both preparations")
	}
}
