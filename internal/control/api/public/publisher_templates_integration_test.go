package public

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherGroupTemplateHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "template_http")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example"
	handler, err := NewHandler(Config{ControlURL: server}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: handler, peer: "10.0.0.2:1234", source: "8.8.8.8"}
	owner, err := clientcontrol.New(server, &http.Client{Transport: transport}, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	group := "tractor"
	configuration := controlv1.ProjectConfiguration{
		PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Template: new(true)}},
		Services:        map[string]controlv1.ProjectServiceConfiguration{"diagnostics": {PublisherGroup: &group, Target: "http://localhost:9080"}},
	}
	applied, err := owner.ApplyProjectConfiguration(ctx, "tractors", controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: configuration})
	if err != nil {
		t.Fatal(err)
	}
	created, err := owner.CreatePublisherGroup(ctx, "tractors", "tractor-042", controlv1.CreatePublisherGroupRequest{TeamId: team, From: group, ExpectedRevision: applied.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if created.GroupName != "tractor-042" || created.Server != server || created.Services["diagnostics"] != "http" || created.GroupId == "" {
		t.Fatalf("wrong descriptor: %+v", created)
	}
	encoded, err := json.Marshal(created)
	if err != nil || strings.Contains(string(encoded), "9080") || strings.Contains(string(encoded), "localhost") {
		t.Fatalf("descriptor leaked target: %s %v", encoded, err)
	}
	read, err := owner.GetPublisherGroupConnection(ctx, team, "tractors", created.GroupId)
	if err != nil || read.GroupId != created.GroupId {
		t.Fatal("cannot recover descriptor", err)
	}
	selected, err := owner.GetProjectService(ctx, "tractors", "diagnostics", controlv1.GetProjectServiceParams{TeamId: team, SourceFingerprint: applied.SourceFingerprint, PublisherGroup: &created.GroupId})
	if err != nil || selected.Id == "" {
		t.Fatal("cannot resolve group service", err)
	}
	if _, err := owner.GetPublisherGroupConnection(ctx, team, "tractors", group); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("template became concrete", err)
	}
	if _, err := owner.CreatePublisherGroup(ctx, "tractors", "tractor-bad", controlv1.CreatePublisherGroupRequest{TeamId: team, From: group, ExpectedRevision: applied.Revision}); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("stale creation committed", err)
	}
	current, err := owner.GetProjectConfiguration(ctx, team, "tractors")
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.RemovePublisherGroup(ctx, team, "tractors", "tractor-042", current.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.GetPublisherGroupConnection(ctx, team, "tractors", created.GroupId); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("retired descriptor recovered", err)
	}
}
