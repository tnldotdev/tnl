package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceConfigurationManagementBoundary(t *testing.T) {
	f, session, recipient, team, service := serviceFixture(t)
	ctx := t.Context()
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	h, err := NewHandler(Config{ControlURL: server.URL}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	newClient := func(token credentials.AccessToken) *clientcontrol.Client {
		t.Helper()
		client, err := clientcontrol.New(server.URL, server.Client(), token)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	owner := newClient(credentials.AccessToken(session.AccessToken))
	visitor := newClient(credentials.AccessToken(recipient.AccessToken))
	empty, emptyDigest, err := owner.GetServiceConfiguration(ctx, service.ID)
	if err != nil || empty != nil || emptyDigest == "" {
		t.Fatal("declaration-free read lost its condition", err)
	}
	privateTarget := "private-listener.internal:3000"
	configuration := &controlv1.ProjectServiceConfiguration{
		Target: "http://" + privateTarget, RequirePostQuantum: new(true),
		Http: &controlv1.ProjectServiceHTTP{
			Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.VisitorAccessMode("anonymous")), Ip: new([]string{"192.0.2.10"})},
			Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(100)},
		},
	}
	updated, err := owner.ConfigureService(ctx, service.ID, controlv1.UpdateServiceRequest{
		Protocol: controlv1.ServiceProtocolHTTP, ExpectedTrustRevision: service.TrustRevision,
		Configuration: configuration, ExpectedConfigurationDigest: &emptyDigest,
	})
	if err != nil || updated.Id != service.ID {
		t.Fatal("conditional declaration creation replaced the service", err)
	}
	read, digest, err := owner.GetServiceConfiguration(ctx, service.ID)
	if err != nil || read == nil || digest == emptyDigest || read.Target != privateTarget || read.Http == nil ||
		read.Http.Access == nil || read.Http.Access.Mode == nil || *read.Http.Access.Mode != "anonymous" ||
		read.RequirePostQuantum == nil || !*read.RequirePostQuantum || read.Http.Limits == nil || read.Http.Limits.Total == nil || *read.Http.Limits.Total != 100 {
		t.Fatal("protected read lost canonical private settings", err)
	}
	read.Http.Limits.Total = new(101)
	next, err := owner.ConfigureService(ctx, service.ID, controlv1.UpdateServiceRequest{
		Protocol: updated.Protocol, PublisherPool: updated.PublisherPool, ExpectedTrustRevision: updated.TrustRevision,
		Configuration: read, ExpectedConfigurationDigest: &digest,
	})
	if err != nil || next.TrustRevision != updated.TrustRevision || next.EndpointRevision != updated.EndpointRevision {
		t.Fatal("policy-only conditional replacement changed trust or placement", err)
	}
	if _, err := owner.ConfigureService(ctx, service.ID, controlv1.UpdateServiceRequest{
		Protocol: next.Protocol, PublisherPool: next.PublisherPool, ExpectedTrustRevision: next.TrustRevision,
		Configuration: read, ExpectedConfigurationDigest: &digest,
	}); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("old declaration digest overwrote a policy-only update", err)
	}
	if _, err := f.d.CreateServiceGrant(ctx, service.ID, session.Identity.Identity.Id, "visitor", "identity", recipient.Identity.Identity.Id, nil, f.now); err != nil {
		t.Fatal(err)
	}
	inventory, err := visitor.ListAvailableServices(ctx, "connector")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, available := range inventory {
		found = found || available.Id == service.ID
	}
	if !found {
		t.Fatal("visitor denial fixture has no real service visit grant")
	}
	if declaration, digest, err := visitor.GetServiceConfiguration(ctx, service.ID); !errors.Is(err, clientcontrol.ErrNotFound) || declaration != nil || digest != "" {
		t.Fatal("visitor grant exposed the protected declaration", err)
	}
	q := controlstatedb.New(f.sql)
	identity, err := f.d.IdentityContext(ctx, session.Identity.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	var member controlstate.Membership
	for _, membership := range identity.Memberships {
		if membership.TeamID == team.ID {
			member = membership
		}
	}
	enrollment, err := f.d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID},
		Name:  "configuration-read", Kind: "installed", EditorID: session.Identity.Identity.Id,
		EditorMembershipID: member.ID, PolicyRevision: uint64(member.PolicyRevision), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	audience := server.URL + "/v1/publisher-token"
	proof, err := publisherproof.Sign(publisher.ID, publisher.KeyID, publisher.GrantID, audience, private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.d.ExchangePublisherAssertion(ctx, publisher.ID, publisher.GrantID, audience, proof, "127.0.0.1", f.now)
	if err != nil {
		t.Fatal(err)
	}
	publisherMetadata, err := newClient("").GetPublisherService(ctx, service.ID, access.Token)
	if err != nil {
		t.Fatal("publisher denial fixture has no real exact-service publication permission", err)
	}
	if declaration, digest, err := newClient(credentials.AccessToken(access.Token)).GetServiceConfiguration(ctx, service.ID); !errors.Is(err, clientcontrol.ErrUnauthenticated) || declaration != nil || digest != "" {
		t.Fatal("publisher credential exposed the protected management declaration", err)
	}
	metadata, err := owner.GetService(ctx, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{inventory, metadata, publisherMetadata} {
		data, err := json.Marshal(value)
		if err != nil || bytes.Contains(data, []byte(privateTarget)) || bytes.Contains(data, []byte("192.0.2.10")) ||
			bytes.Contains(data, []byte(`"configuration"`)) || bytes.Contains(data, []byte(`"access"`)) {
			t.Fatal("private declaration escaped through service inventory or metadata", err)
		}
	}
	stored, err := q.GetServiceConfiguration(ctx, service.ID)
	if err != nil || len(stored.ConfigurationCiphertext) == 0 {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(stored.ConfigurationCiphertext)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service.ID, Ciphertext: corrupt, StorageKeyID: stored.StorageKeyID}); err != nil {
		t.Fatal(err)
	}
	if declaration, digest, err := owner.GetServiceConfiguration(ctx, service.ID); !errors.Is(err, clientcontrol.ErrNotFound) || declaration != nil || digest != "" {
		t.Fatal("corrupt declaration returned configuration or a usable digest", err)
	}
}
