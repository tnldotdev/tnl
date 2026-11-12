package group_test

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
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
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
	now := time.Now().UTC().Add(-3 * time.Minute)
	session, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, actor := session.Identity.PersonalTeamID, session.Identity.Identity.ID
	const project, instance = "shop", "replica-1"
	definition, err := database.CreateServiceDefinition(ctx, controlstate.CreateServiceDefinitionRequest{TeamID: team, ActorID: actor, ProjectKey: project, SourceFingerprint: strings.Repeat("a", 64), Now: now, Definition: controlstate.ServiceDefinition{Services: map[string]controlstate.ServiceDefinitionService{"api": {Protocol: "http"}}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := database.AuthenticateEnvironmentPublisherManager(ctx, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := database.CreateEnvironment(ctx, controlstate.CreateEnvironmentRequest{Manager: manager, TeamID: team, ActorID: actor, ProjectKey: project, SourceFingerprint: strings.Repeat("a", 64), Name: "production", DefinitionRevision: definition.Revision, Targets: controlstate.EnvironmentTargets{"api": {Address: "http://api.internal:3000"}}, IdempotencyKey: "production", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	selection := controlstate.EnvironmentPublisherSelection{TeamID: team, ProjectKey: project, EnvironmentID: environment.ID, Manager: manager}
	// expire the one-member bootstrap in the database's clock before replacement;
	// tasks must use signing proof, not rely on idempotent enrollment redemption.
	enrollment, err := database.IssueEnvironmentPublisherEnrollment(ctx, controlstate.IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: selection, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, Now: now.Add(30 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := database.RedeemEnvironmentPublisherEnrollment(ctx, enrollment.Key, public, now.Add(40*time.Second))
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
		if r.URL.Path == "/v1/environment-publishers/enroll" {
			enrollmentRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	client, err := publishergroup.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	// the portable member is the wire result of the same real control store.
	wireMember := controlv1.EnvironmentPublisher{TeamId: member.TeamID, ProjectKey: member.ProjectKey, EnvironmentId: member.EnvironmentID, PublisherIdentityId: member.PublisherIdentityID, KeyId: member.KeyID}
	value, err := credentialfile.NewGroup(server.URL, instance, wireMember, private)
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "replica.json")
	if err := credentialfile.WriteGroup(secret, value); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	for replacement := range 3 {
		encoded, err := os.ReadFile(secret)
		if err != nil {
			t.Fatal(err)
		}
		injected, err := credentialfile.ParseGroup(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := credentialfile.VerifyGroup(ctx, client, injected, server.URL, project, environment.ID, instance); err != nil {
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
		lock, err := profile.LockPublisherSigningIdentity(ctx, credentialfile.GroupSelection(project, environment.ID, instance))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := credentialfile.ImportGroup(ctx, profile, injected, server.URL, project, environment.ID, instance)
		if err != nil || !bytes.Equal(restored, private) {
			t.Fatal("replacement changed its key", err)
		}
		selected, found, err := profile.SelectedPublisherIdentity(ctx, "project", credentialfile.GroupSelection(project, value.Member.EnvironmentId, instance))
		if err != nil || !found || selected.ID != member.PublisherIdentityID || !bytes.Equal(selected.SigningKey, private) {
			t.Fatal("replacement did not install the original identity", err)
		}
		_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrong := injected
		wrong.PrivateKey = base64.RawURLEncoding.EncodeToString(wrongKey)
		if err := credentialfile.VerifyGroup(ctx, client, wrong, server.URL, project, environment.ID, instance); err == nil {
			t.Fatal("real control accepted another key for this member")
		}
		if _, err := credentialfile.ImportGroup(ctx, profile, wrong, server.URL, project, environment.ID, instance); !errors.Is(err, clientstate.ErrPublisherStateConflict) {
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
	status, err := database.ListEnvironmentPublishers(ctx, selection)
	if err != nil || len(status) != 1 || status[0].PublisherIdentityID != member.PublisherIdentityID || enrollmentRequests.Load() != 0 {
		t.Fatal("replacements enrolled another identity or used bootstrap", err)
	}
	if _, err := client.Enroll(ctx, enrollment.Key, public); err == nil {
		t.Fatal("expired enrollment unexpectedly succeeded")
	}
	if err := database.RevokeEnvironmentPublisher(ctx, selection, member.PublisherIdentityID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := credentialfile.VerifyGroup(ctx, client, value, server.URL, project, environment.ID, instance); err == nil {
		t.Fatal("restored secret bypassed member revocation")
	}
}
