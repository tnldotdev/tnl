package deployment_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// exercise identity replacement with real control HTTP,
// PostgreSQL authorization and disposable file-protected SQLite. no AWS calls.
func TestIntegrationPublisherIdentitySurvivesTaskStateDeletion(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "publisher_replacement")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, actor := session.Identity.PersonalTeamID, session.Identity.Identity.ID
	const project, deployment, instance = "shop", "production", "replica-1"
	_, err = database.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{Deployment: deployment, ServiceDeclarations: map[string]string{"api": "http"}, TeamID: team, ActorID: actor, ProjectKey: project, SourceFingerprint: strings.Repeat("a", 64), Now: now, Configuration: controlstate.ProjectConfiguration{
		Settings: &controlstate.DeploymentSettings{},
		Services: map[string]controlstate.ProjectServiceConfiguration{"api": {Target: "api.internal:3000"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// expire the one-member bootstrap in the database's clock before replacement;
	// tasks must use signing proof, not rely on idempotent enrollment redemption.
	enrollment, err := database.CreateDeploymentPublisherEnrollment(ctx, controlstate.CreateDeploymentPublisherEnrollmentRequest{
		DeploymentScope: controlstate.DeploymentScope{TeamID: team, ProjectKey: project, ActorID: actor}, Selector: deployment,
		Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, Now: now.Add(-2 * time.Minute), IdempotencyKey: "replacement-enrollment",
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := database.RedeemDeploymentPublisherEnrollment(ctx, enrollment.Key, public, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	handler, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL}, controlpublic.DatabaseStores(database), database, nil)
	if err != nil {
		t.Fatal(err)
	}
	var enrollmentRequests atomic.Int64
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/publisher/deployments/enroll" {
			enrollmentRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	client, err := publisherdeployment.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	// the portable member is the wire result of the same real control store.
	wireMember := controlv1.DeploymentPublisherIdentity{TeamId: member.TeamID, ProjectKey: member.ProjectKey, DeploymentName: member.DeploymentName, DeploymentId: member.DeploymentID, PublisherIdentityId: member.PublisherIdentityID, KeyId: member.KeyID}
	value, err := credentialfile.NewDeployment(server.URL, instance, wireMember, private)
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "replica.json")
	if err := credentialfile.WriteDeployment(secret, value); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	for replacement := range 3 {
		encoded, err := os.ReadFile(secret)
		if err != nil {
			t.Fatal(err)
		}
		injected, err := credentialfile.ParseDeployment(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := credentialfile.VerifyDeployment(ctx, client, injected, server.URL, project, deployment, instance); err != nil {
			t.Fatalf("replacement %d could not authenticate its restored key: %v", replacement, err)
		}
		lease, err := client.Lease(ctx, injected.Member, private)
		if err != nil {
			t.Fatal(err)
		}
		assignments, err := client.Assignments(ctx, lease.AccessToken)
		if err != nil || assignments.CertificateStatePlans == nil || len(assignments.CertificateStatePlans) != 0 {
			t.Fatal("real control HTTP did not preserve the precise fresh recovery contract", err)
		}
		state, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		profile, err := state.Server(ctx, server.URL)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := profile.LockPublisherSigningIdentity(ctx, credentialfile.DeploymentSelection(project, deployment, instance))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := credentialfile.ImportDeployment(ctx, profile, injected, server.URL, project, deployment, instance)
		if err != nil || !bytes.Equal(restored, private) {
			t.Fatal("replacement changed its key", err)
		}
		selected, found, err := profile.SelectedPublisherIdentity(ctx, "project", credentialfile.DeploymentSelection(project, value.Member.DeploymentId, instance))
		if err != nil || !found || selected.ID != member.PublisherIdentityID || !bytes.Equal(selected.SigningKey, private) {
			t.Fatal("replacement did not install the original identity", err)
		}
		_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrong := injected
		wrong.PrivateKey = base64.RawURLEncoding.EncodeToString(wrongKey)
		if err := credentialfile.VerifyDeployment(ctx, client, wrong, server.URL, project, deployment, instance); err == nil {
			t.Fatal("real control accepted another key for this member")
		}
		if _, err := credentialfile.ImportDeployment(ctx, profile, wrong, server.URL, project, deployment, instance); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
			t.Fatal("a mismatched key replaced installed state", err)
		}
		_ = lock.Close()
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
	}
	status, err := database.GetProjectConfiguration(ctx, team, project, actor, "production")
	if err != nil || len(status.Members) != 1 || status.Members[0].PublisherIdentityID != member.PublisherIdentityID || enrollmentRequests.Load() != 0 {
		t.Fatal("replacements enrolled another identity or used bootstrap", err)
	}
	if _, err := client.Enroll(ctx, enrollment.Key, public); err == nil {
		t.Fatal("expired enrollment unexpectedly succeeded")
	}
	if err := database.RevokeDeploymentPublisher(ctx, controlstate.DeploymentScope{TeamID: team, ProjectKey: project, ActorID: actor}, deployment, member.PublisherIdentityID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := credentialfile.VerifyDeployment(ctx, client, value, server.URL, project, deployment, instance); err == nil {
		t.Fatal("restored secret bypassed member revocation")
	}
}
