package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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
	if err := d.PrepareVisitorSigningKeys(ctx, server.URL, now); err != nil {
		t.Fatal(err)
	}
	issuer := githubtest.New(t)
	if _, err = controlauthority.Register(mux, controlauthority.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	owner, err := clientcontrol.New(server.URL, server.Client(), human.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	group, protocol := "production", controlv1.Kubernetes
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}, Environment: new("ci"), JobWorkflowRef: new("example/shared/.github/workflows/reuse.yml@refs/tags/v1")}, Services: []string{"cluster"}, MaxDurationSeconds: 3600}}
	body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"cluster": {PublisherGroup: &group, Protocol: &protocol, Target: "", TargetDiscovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Eks, Region: "us-east-1", Cluster: new("production")}}}, Webhooks: map[string]controlv1.ProjectWebhook{}}}
	applied, err := owner.ApplyProjectConfiguration(ctx, "example", body)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Configuration.Services["cluster"].TargetDiscovery == nil || applied.Configuration.Services["cluster"].Target != "" {
		t.Fatal("cloud selector did not survive apply")
	}
	job, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	claims := githubtest.Claims(server.URL, now)
	claims["environment"] = "ci"
	claims["job_workflow_ref"] = "example/shared/.github/workflows/reuse.yml@refs/tags/v1"
	assertion := issuer.Sign(t, claims)
	session, err := job.Exchange(ctx, team, "example", body.SourceFingerprint, "test", assertion, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g := session.Github; g == nil || g.RepositoryId != "12345" || g.RepositoryOwnerId != "6789" || g.RunId != "111" || g.RunAttempt != "1" || g.CheckRunId != "222" {
		t.Fatal("GitHub session omitted signed execution metadata")
	}
	retry, err := job.Exchange(ctx, team, "example", body.SourceFingerprint, "test", assertion, nil)
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
	humanServices, err := owner.ListAvailableServices(ctx)
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
		if _, err = job.Exchange(ctx, team, "example", body.SourceFingerprint, "test", issuer.Sign(t, mutated), nil); err == nil {
			t.Fatalf("HTTP accepted wrong %s", bad.field)
		}
	}
	workloadControl, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	body.ExpectedRevision = applied.Revision
	if _, err = workloadControl.ApplyProjectConfiguration(ctx, "example", body); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("workload self-applied policy", err)
	}
	if _, err = workloadControl.GetProjectConfiguration(ctx, team, "example"); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("workload read manager target inventory", err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.IdentityContext(ctx); !errors.Is(err, clientauthority.ErrUnauthenticated) {
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
	t.Run("retained and collected deletion ownership", func(t *testing.T) {
		requestStatus := func(method, path, credential string, want int) {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, method, server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+credential)
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != want {
				t.Fatalf("%s %s: status=%d want=%d err=%v", method, path, response.StatusCode, want, err)
			}
			if bytes.Contains(data, []byte(credential)) {
				t.Fatal("deletion response exposed a bearer credential")
			}
		}
		for i, name := range []string{"lease-expired", "old-expired", "old-revoked"} {
			at := now.Add(-40 * 24 * time.Hour)
			if i == 0 {
				at = now.Add(-2 * time.Minute)
			}
			// historical verifier-produced state uses the store's explicit clock;
			// all HTTP handlers and cleanup below run at the actual current time.
			encoded, _ := json.Marshal(claims)
			var g oidc.GitHubExecution
			if err := json.Unmarshal(encoded, &g); err != nil {
				t.Fatal(err)
			}
			g.JTI, g.CheckRunID = name, fmt.Sprint(9000+i)
			g.IssuedAt, g.NotBefore, g.ExpiresAt = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			c := oidc.WorkloadExecution{Provider: "github", Issuer: oidc.GitHubIssuer, Subject: g.Subject, GitHub: &g, IssuedAt: g.IssuedAt, NotBefore: g.NotBefore, ExpiresAt: g.ExpiresAt, AssertionDigest: sha256.Sum256([]byte(name))}
			exchange := controlstate.ExchangeWorkloadRequest{TeamID: team, ProjectKey: "example", Workload: "test", SourceFingerprint: body.SourceFingerprint, Nonce: rand.Text(), Execution: c, PublicKey: public}
			exchange.Signature = ed25519.Sign(key, workloadproof.Exchange(team, "example", "test", body.SourceFingerprint, exchange.Nonce, c.AssertionDigest, nil))
			s, err := d.ExchangeWorkload(ctx, exchange, at)
			if err != nil {
				t.Fatal(err)
			}
			runID, err := opaqueid.New(opaqueid.IngressRunPrefix)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: name, IngressRunID: runID, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, ConnectorAddress: name + ".example.test:9443", ConnectorTLSServerName: name + ".example.test", IngressPoolID: controlstate.PrimaryIngressPoolID}, at, time.Hour); err != nil {
				t.Fatal(err)
			}
			handles, err := d.CreateWorkloadIngressAssignmentSet(ctx, s.Credential, service, "retention", 1, "", at)
			if err != nil {
				t.Fatal(err)
			}
			if name == "old-revoked" {
				if err := d.RevokeWorkloadSession(ctx, s.ID, s.Credential, at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			if name != "lease-expired" {
				if err := d.ReleaseWorkloadIngressAssignment(ctx, s.Credential, handles.Assignments[0].ID, at.Add(2*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			sessionPath := "/v1/workload-sessions/" + s.ID
			handlePath := "/v1/workload/ingress-assignments/" + handles.Assignments[0].ID
			for range 2 {
				requestStatus("DELETE", handlePath, s.Credential, 204)
				requestStatus("DELETE", handlePath, session.Credential, 403)
				requestStatus("DELETE", sessionPath, session.Credential, 403)
				if name != "old-expired" {
					requestStatus("DELETE", sessionPath, s.Credential, 204)
				}
				requestStatus("POST", sessionPath+"/renew", s.Credential, 403)
			}
			if name == "lease-expired" {
				continue
			}
			for range 10 {
				n, err := d.CleanupWorkloads(ctx, time.Now(), 1000)
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					break
				}
			}
			for range 2 {
				requestStatus("DELETE", handlePath, s.Credential, 403)
				requestStatus("DELETE", sessionPath, s.Credential, 403)
				requestStatus("POST", sessionPath+"/renew", s.Credential, 403)
			}
		}
	})
}
