package control_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentPublisherClient(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_publisher_client")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(t.Context(), database, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	_, err = database.ApplyProjectConfiguration(t.Context(), controlstate.ApplyProjectConfigurationRequest{TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "shop", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{Services: map[string]controlstate.ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: "localhost:5432"}, "cache": {Protocol: "tcp", Target: "localhost:6379"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	handler, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, controlpublic.DatabaseStores(database), database, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", handler)
	client, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string) controlv1.Deployment {
		t.Helper()
		deployment, err := client.CreateDeployment(t.Context(), team, "shop", "create-"+name, controlv1.CreateDeploymentRequest{Name: name, Targets: controlv1.DeploymentTargets{"db": {Address: "db.internal:5432"}, "cache": {Address: "cache.internal:6379"}}})
		if err != nil {
			t.Fatal(err)
		}
		return deployment
	}
	selected, sibling := create("selected"), create("sibling")
	members, seconds := 1, 600
	body := controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"db"}, MaxMembers: &members, ExpiresIn: &seconds}
	enrollment, err := client.CreateDeploymentPublisherEnrollment(t.Context(), team, "shop", selected.Id, "original-setup", body)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := client.CreateDeploymentPublisherEnrollment(t.Context(), team, "shop", selected.Id, "original-setup", body)
	if err != nil || recovered.EnrollmentKey != enrollment.EnrollmentKey || !recovered.ExpiresAt.Equal(enrollment.ExpiresAt) || len(recovered.Services) != 1 || recovered.Services["db"] != controlv1.Postgres {
		t.Fatal("real setup recovery changed exact scope, secret, or deadline", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemPublisherGroupEnrollment(t.Context(), enrollment.EnrollmentKey, public)
	if err != nil || member.GroupId != selected.Id {
		t.Fatal("existing group enrollment did not accept scoped setup", err)
	}
	page, err := client.ListDeploymentPublishers(t.Context(), team, "shop", selected.Id, "", 1)
	if err != nil || len(page.Publishers) != 1 || page.Publishers[0].PublisherIdentityId != member.PublisherIdentityId || len(page.Publishers[0].Services) != 1 || page.Publishers[0].Services["db"] != controlv1.Postgres {
		t.Fatal("real publisher observation broadened its captured service scope", err)
	}
	if err := client.RevokeDeploymentPublisher(t.Context(), team, "shop", sibling.Id, member.PublisherIdentityId); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("sibling deployment revoked the selected publisher", err)
	}
	if err := client.RevokeDeploymentPublisher(t.Context(), team, "shop", selected.Id, member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeDeploymentPublisher(t.Context(), team, "shop", selected.Id, member.PublisherIdentityId); err != nil {
		t.Fatal("exact revocation was not repeatable", err)
	}
	page, err = client.ListDeploymentPublishers(t.Context(), team, "shop", selected.Id, "", 1)
	if err != nil || len(page.Publishers) != 1 || page.Publishers[0].RevokedAt == nil {
		t.Fatal("revocation lost its retained observation", err)
	}
	if result, err := client.CreateDeploymentPublisherEnrollment(t.Context(), team, "shop", selected.Id, "original-setup", body); !errors.Is(err, clientcontrol.ErrStatusConflict) || result.EnrollmentKey != "" {
		t.Fatal("exhausted enrollment replay restored authority or exposed a secret", err)
	}
}
