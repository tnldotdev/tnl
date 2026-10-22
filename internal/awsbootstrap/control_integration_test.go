package awsbootstrap

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/awsfixture"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationAWSBootstrapAppliedGroup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "aws_bootstrap")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	handler, err := controlapi.NewHandler(controlapi.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var lose atomic.Bool
	lose.Store(true)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/publisher-groups/enroll" && lose.CompareAndSwap(true, false) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != 200 && response.Code != 201 {
				t.Error("real enrollment did not commit", response.Code)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		handler.ServeHTTP(w, r)
	}))
	owner, err := controlclient.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	group := "production"
	applied, err := owner.ApplyProjectConfiguration(ctx, "shop", controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Publishers: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Publisher: &group, Target: "http://not-yet-created.internal:3000"}}}})
	if err != nil || applied.Groups == nil || len(*applied.Groups) != 1 {
		t.Fatal("real apply", err)
	}
	groupID := (*applied.Groups)[0].Id
	client, err := grouppublisher.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	db, err := clientstate.OpenWithOptions(ctx, filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := clientstate.OpenPrivateDirectory(filepath.Join(root, ".tnl", "local", "aws"))
	if err != nil {
		t.Fatal(err)
	}
	aws := awsfixture.New(t)
	secrets, caller := aws.Clients()
	if err := CheckAccount(ctx, caller, awsfixture.Account); err != nil {
		t.Fatal(err)
	}
	p := Preparer{Store: store, Secrets: secrets, Control: owner, Client: client, Receipts: receipts}
	r := Request{Binding: Binding{ControlOrigin: server.URL, TeamID: team, GroupID: groupID, ProjectKey: "shop", SourceFingerprint: applied.SourceFingerprint, AccountID: awsfixture.Account, Region: awsfixture.Region, DeploymentName: "production", ReplicaSlot: "replica-1"}, Group: group}
	if _, err := p.Prepare(ctx, r); err == nil {
		t.Fatal("lost real enrollment reply reported success")
	}
	ref, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Prepare(ctx, r)
	if err != nil || again != ref {
		t.Fatal("real identity changed", err)
	}
	current, err := owner.GetProjectConfiguration(ctx, team, "shop")
	if err != nil || len(current.Members) != 1 || current.Members[0].PublisherIdentityId != ref.PublisherIdentityID {
		t.Fatal("duplicate control member", err)
	}
	if _, err := owner.RenamePublisherGroup(ctx, "shop", group, controlv1.RenamePublisherGroupRequest{TeamId: team, Name: "live", ExpectedRevision: current.Revision}); err != nil {
		t.Fatal(err)
	}
	r.Group = "live"
	if renamed, err := p.Prepare(ctx, r); err != nil || renamed != ref {
		t.Fatal("rename replaced binding", err)
	}
	if err := owner.RevokePublisherGroupMember(ctx, team, "shop", "live", ref.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Prepare(ctx, r); err == nil {
		t.Fatal("revoked identity reported prepared")
	}
}
