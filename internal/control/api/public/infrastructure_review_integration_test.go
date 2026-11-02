package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPoolAndIngressCertificateHTTPReview(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "infra_http_review")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(ctx, session.Identity.Identity.ID, m.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	if _, err = controlauthority.Register(handler, controlauthority.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	api, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	auth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	pool := true
	membership := m.ID
	body := controlv1.CreatePublicURLRequest{TeamId: m.TeamID, DomainId: domains[0].ID, MembershipId: &membership, CanonicalHostname: "pool." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000",
		PublicUrlScope: controlv1.Member, Purpose: controlv1.App, PublisherPool: &pool}
	created, err := api.CreatePublicURLWithResponse(ctx, &controlv1.CreatePublicURLParams{IdempotencyKey: "pool"}, body, auth)
	if err != nil || created.JSON201 == nil || created.JSON201.PublisherPool == nil || !*created.JSON201.PublisherPool {
		t.Fatalf("authorized pool API field missing: %+v %v", created, err)
	}
	pool = false
	retry, err := api.CreatePublicURLWithResponse(ctx, &controlv1.CreatePublicURLParams{IdempotencyKey: "pool"}, body, auth)
	if err != nil || retry.StatusCode() != 409 {
		t.Fatalf("pool intent not bound to creation retry: %+v %v", retry, err)
	}
	if anonymous, err := api.CreatePublicURLWithResponse(ctx, &controlv1.CreatePublicURLParams{IdempotencyKey: "anonymous"}, body); err != nil || anonymous.StatusCode() != 401 {
		t.Fatalf("anonymous pool configuration accepted: %+v %v", anonymous, err)
	}
	secret := strings.Repeat("x", 32)
	secrets, err := serviceapi.NewBearerSecrets(secret, "")
	if err != nil {
		t.Fatal(err)
	}
	connectionHandler, err := controlingress.NewHandler(controlingress.Config{Store: d, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	privateServer := httptest.NewTLSServer(connectionHandler)
	t.Cleanup(privateServer.Close)
	nodeAPI, err := ingressv1.NewClientWithResponses(privateServer.URL, ingressv1.WithHTTPClient(privateServer.Client()))
	if err != nil {
		t.Fatal(err)
	}
	nodeAuth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+secret)
		return nil
	}
	for _, id := range []string{"ingress-a", "ingress-b"} {
		run, _ := opaqueid.New(opaqueid.IngressRunPrefix)
		body := ingressv1.IngressRegistration{IngressId: id, IngressRunId: run, IngressPoolId: "ingress-a", ServicePorts: []int{}, ProtocolVersion: 1, ConnectionCapacity: 8}
		if unauthorized, err := nodeAPI.RegisterIngressWithResponse(ctx, body); err != nil || unauthorized.StatusCode() != http.StatusUnauthorized {
			t.Fatal("unauthenticated ingress registration", err)
		}
		registration, err := nodeAPI.RegisterIngressWithResponse(ctx, body, nodeAuth)
		if err != nil || registration.JSON200 == nil {
			t.Fatalf("register private endpoint: %+v %v", registration, err)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, privateServer.URL+"/internal/v1/ingresses/"+id+"/transport-certificate", strings.NewReader(`{}`))
		if err := nodeAuth(ctx, request); err != nil {
			t.Fatal(err)
		}
		response, err := privateServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatal("retired ingress certificate API remains served", response.StatusCode)
		}
	}
}
