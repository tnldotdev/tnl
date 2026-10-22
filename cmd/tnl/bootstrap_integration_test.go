package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/awsbootstrap"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisherdeployment"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/awsfixture"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/zalando/go-keyring"
)

func TestIntegrationAWSBootstrapCLI(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	keyring.MockInit()
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "aws_bootstrap_cli")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	session, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	control, err := controlapi.NewHandler(controlapi.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple, OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, database, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityapi.NewHandler(authorityapi.Config{ControlURL: server.URL, ManagedDomain: "example.test", OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, database)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := authority.Handler(r)
		if pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			control.ServeHTTP(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/customer/project.git"}} {
		if output, err := exec.CommandContext(ctx, "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v %s", err, output)
		}
	}
	configFile := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(configFile, []byte(`{"version":1,"tnl":{"publishers":{"production":{"aws":{"replicas":2}}},"services":{"api":{"publisher":"production","target":{"type":"address","address":"http://uncreated.internal:3000"}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := loadProjectConfigurationWithSalt(ctx, cli{ConfigPath: configFile}, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	remote := scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: server.URL, AccessToken: session.AccessToken.String(), StateDir: filepath.Join(root, "state")}, teamSelectionFlags: teamSelectionFlags{Team: team}}
	if err := runApply(ctx, applyCommand{scopedTeamFlags: remote, Output: statusOutputJSON}, project, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := publisherdeployment.Generate(project.Config, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Write(filepath.Join(root, publisherdeployment.DefaultOutputDir)); err != nil {
		t.Fatal(err)
	}
	customer := filepath.Join(root, "aws.json")
	if err := os.WriteFile(customer, []byte(`{"schema_version":1,"deployments":[{"name":"east","publisher":"production","account_id":"123456789012","region":"us-east-1"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	f := awsfixture.New(t)
	secrets, caller := f.Clients()
	load := func(context.Context, string, string) (awsbootstrap.Secrets, awsbootstrap.Caller, error) {
		return secrets, caller, nil
	}
	flags := bootstrapCommand{scopedTeamFlags: remote, Publisher: "production", DeploymentFile: customer, GeneratedDir: publisherdeployment.DefaultOutputDir, Output: statusOutputJSON}
	var output bytes.Buffer
	if err := runBootstrapUsing(ctx, flags, project, &output, io.Discard, load); err != nil {
		t.Fatal(err)
	}
	var result bootstrapResult
	if json.Unmarshal(output.Bytes(), &result) != nil || result.State != "prepared" || len(result.Replicas) != 2 || len(result.Parameters) != 15 || len(result.ObservedMembers) != 0 || result.TemplateVersion != publisherdeployment.TemplateVersion {
		t.Fatal("bootstrap did not compile the actual generated parameter contract")
	}
	for _, ref := range result.Replicas {
		value, err := credentialfile.ParseGroup([]byte(f.Value(ref.SecretARN, ref.SecretVersion)))
		if err != nil || bytes.Contains(output.Bytes(), []byte(value.PrivateKey)) {
			t.Fatal("CLI output contains private identity")
		}
	}
	before := len(f.Calls())
	output.Reset()
	if err := runBootstrapUsing(ctx, flags, project, &output, io.Discard, load); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.State != "prepared" || len(result.ObservedMembers) != 0 {
		t.Fatal("enrollment was presented as an observed deployment")
	}
	output.Reset()
	flags.Output = "human"
	if err := runBootstrapUsing(ctx, flags, project, &output, io.Discard, load); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[ tnl bootstrap ]") || !strings.Contains(output.String(), "prepared") || !strings.Contains(output.String(), "not observed") {
		t.Fatal("missing finite human frame")
	}
	for _, call := range f.Calls()[before:] {
		if call.Operation == "CreateSecret" || call.Operation == "PutSecretValue" {
			t.Fatal("CLI retry changed AWS state")
		}
	}
	// customer overrides cannot retarget a bootstrap-owned identity parameter.
	if err := os.WriteFile(customer, []byte(`{"schema_version":1,"deployments":[{"name":"east","publisher":"production","account_id":"123456789012","region":"us-east-1","parameters":{"ControlURL":"https://other.invalid"}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	before = len(f.Calls())
	if err := runBootstrapUsing(ctx, flags, project, io.Discard, io.Discard, load); err == nil || len(f.Calls()) != before {
		t.Fatal("customer scope override reached AWS")
	}
}
