package controlapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/internal/workloadclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationWorkloadHTTPAndNativeAdapter(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "workload_http")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	human, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team := human.Identity.Memberships[0].TeamID
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuer := githubtest.New(t)
	if _, err = authorityapi.Register(mux, authorityapi.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	owner, err := controlclient.New(server.URL, server.Client(), human.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	group, protocol := "production", controlv1.Kubernetes
	policies := map[string]controlv1.ProjectCI{"test": {Github: controlv1.ProjectCIGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}, Environment: new("ci"), JobWorkflowRef: new("example/shared/.github/workflows/reuse.yml@refs/tags/v1")}, Services: []string{"cluster"}, MaxDurationSeconds: 3600}}
	body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Ci: &policies, Publishers: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"cluster": {Publisher: &group, Protocol: &protocol, Target: "", TargetDiscovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Eks, Region: "us-east-1", Cluster: new("production")}}}, Webhooks: map[string]controlv1.ProjectWebhook{}}}
	applied, err := owner.ApplyProjectConfiguration(ctx, "example", body)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Configuration.Services["cluster"].TargetDiscovery == nil || applied.Configuration.Services["cluster"].Target != "" {
		t.Fatal("cloud selector did not survive apply")
	}
	job, err := workloadclient.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	claims := githubtest.Claims(server.URL, now)
	claims["environment"] = "ci"
	claims["job_workflow_ref"] = "example/shared/.github/workflows/reuse.yml@refs/tags/v1"
	assertion := issuer.Sign(t, claims)
	session, err := job.Exchange(ctx, team, "example", "test", assertion, nil)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := job.Exchange(ctx, team, "example", "test", assertion, nil)
	if err != nil || retry.Id != session.Id || retry.Credential != session.Credential || !retry.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatal("HTTP lost-reply recovery changed execution", err)
	}
	services, err := job.ListServices(ctx)
	if err != nil || len(services.Services) != 1 || services.Services[0].Protocol != controlv1.Kubernetes {
		t.Fatal("native workload inventory", services, err)
	}
	service := services.Services[0].Id
	hint := services.Services[0].KubernetesAuth
	if hint == nil || hint.Provider != controlv1.KubernetesEKS || hint.Cluster != "production" || hint.Region != "us-east-1" {
		t.Fatal("missing approved native Kubernetes auth hint")
	}
	humanServices, err := owner.ListAvailablePrivateServices(ctx)
	if err != nil || len(humanServices) != 1 || humanServices[0].KubernetesAuth == nil || *humanServices[0].KubernetesAuth != *hint {
		t.Fatal("human inventory lost approved auth hint", err)
	}
	if decision, err := job.CheckService(ctx, service); err != nil || decision.Subject.WorkloadSessionId == nil || *decision.Subject.WorkloadSessionId != session.Id {
		t.Fatal("native workload authorization", decision, err)
	}
	if _, err = job.ServiceClientCertificate(ctx, service); err != nil {
		t.Fatal("workload public-path certificate", err)
	}
	if certificate, err := job.ClientTLSCertificate(ctx, service); err != nil || certificate.PrivateKey == nil || certificate.Leaf == nil {
		t.Fatal("native workload TLS adapter", err)
	}
	if renewed, err := job.Renew(ctx); err != nil || !renewed.ExpiresAt.Equal(session.ExpiresAt) || !renewed.LeaseExpiresAt.Equal(session.LeaseExpiresAt) {
		t.Fatal("early renewal extended execution", err)
	}
	for _, bad := range []struct {
		field string
		value any
	}{{"repository_id", "999"}, {"repository_owner_id", "999"}, {"environment", "production"}, {"job_workflow_ref", "example/shared/.github/workflows/reuse.yml@refs/tags/v2"}, {"ref", "refs/heads/other"}} {
		mutated := githubtest.Claims(server.URL, now)
		mutated["environment"] = "ci"
		mutated["job_workflow_ref"] = "example/shared/.github/workflows/reuse.yml@refs/tags/v1"
		mutated[bad.field] = bad.value
		if _, err = job.Exchange(ctx, team, "example", "test", issuer.Sign(t, mutated), nil); err == nil {
			t.Fatalf("HTTP accepted wrong %s", bad.field)
		}
	}
	workloadControl, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	body.ExpectedRevision = applied.Revision
	if _, err = workloadControl.ApplyProjectConfiguration(ctx, "example", body); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("workload self-applied policy", err)
	}
	if _, err = workloadControl.GetProjectConfiguration(ctx, team, "example"); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("workload read manager target inventory", err)
	}
	authority, err := authorityclient.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.IdentityContext(ctx); !errors.Is(err, authorityclient.ErrUnauthenticated) {
		t.Fatal("workload became a human control session", err)
	}
	if _, err = workloadControl.GetPublisherGroupAssignments(ctx, session.Credential); err == nil {
		t.Fatal("workload became a publisher")
	}
	// verify actual response bodies contain no assertion, provider selector or
	// application credential in visitor inventory and error envelopes.
	for _, path := range []string{"/v1/workload/services", "/v1/identity"} {
		request, _ := http.NewRequestWithContext(ctx, "GET", server.URL+path, nil)
		request.Header.Set("Authorization", "Bearer "+session.Credential)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(assertion)) || bytes.Contains(data, []byte("target_discovery")) || bytes.Contains(data, []byte(session.Credential)) {
			t.Fatal("visitor response leaked credential or target configuration")
		}
	}
	if err = job.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = job.CheckService(ctx, service); err == nil {
		t.Fatal("revoked workload retained visitor access")
	}
	// human administration remains independently usable after job revocation.
	if _, err = owner.GetProjectConfiguration(ctx, team, "example"); err != nil {
		t.Fatal(err)
	}
}
