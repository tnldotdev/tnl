package state

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
)

func TestIntegrationSavedAliasTargetStaysLocalThroughPolicyUpdates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_app_target")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Target: "app"}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "app",
		ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	declaration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.10/32"}}}
	updated, err := d.ConfigureService(t.Context(), service.ID, actor.ActingIdentityID, service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, now.Add(time.Second))
	if err != nil || updated.TrustRevision != service.TrustRevision || updated.Endpoint.Hostname != service.Endpoint.Hostname {
		t.Fatal("policy update changed target trust or endpoint", err)
	}
	loaded, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || loaded.Target != "app" {
		t.Fatal("app-owned target was replaced by a server address", err)
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.services WHERE id=$1`, service.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("192.0.2.10")) {
		t.Fatal("configuration policy was not encrypted", err)
	}
}

func TestIntegrationSavedAliasServiceKeepsIndependentPolicyAndShares(t *testing.T) {
	f := newServiceHTTPFixture(t)
	// aliases use their own saved service and visitor hostname even when their
	// selected application listener is identical. receiver selection lives locally.
	entry := f
	entry.service = f.local(t, "entry", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	entry.run = entry.publish(t, entry.service)
	f.run = f.publish(t, f.service)
	for _, test := range []struct {
		fixture   serviceHTTPFixture
		anonymous bool
	}{{entry, true}, {f, false}} {
		auth := test.fixture.auth()
		wire, err := f.database.ReadPublisherVisitorPolicy(t.Context(), auth.Subject, auth.RunID, auth.Number, auth.Token.String(), 0, f.now)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(wire)
		if err != nil || update.Anonymous != test.anonymous || update.View.Scope != auth.Subject {
			t.Fatal("alias and entry service did not expose their independent visitor policies", err)
		}
	}
	preview := f.preview(t, "entry-only", entry.service)
	secret := bytes.Repeat([]byte{31}, 32)
	share := f.share(t, preview.ID, "entry-share", secret, entry.service)
	session, err := f.database.RedeemShare(t.Context(), entry.auth(), share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, f.now); !errors.Is(err, ErrShareNotFound) {
		t.Fatal("entry share was redeemable on the alias service", err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: session.CookieSecret}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, source, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("entry share cookie granted alias permission", err)
	}
	aliasSecret := bytes.Repeat([]byte{32}, 32)
	aliasShare := f.share(t, "", "alias-share", aliasSecret, f.service)
	aliasSession, err := f.database.RedeemShare(t.Context(), f.auth(), aliasShare.ID, aliasSecret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RevokeShare(t.Context(), share.ID, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	aliasSource := ShareSessionTokenSource{ShareID: aliasShare.ID, Secret: aliasSession.CookieSecret}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, aliasSource, f.now); err != nil {
		t.Fatal("entry-share revocation revoked the independent alias share", err)
	}
}
