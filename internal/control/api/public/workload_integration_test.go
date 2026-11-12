package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadHTTPAndNativeAdapter(t *testing.T) {
	f := newRetainedVisitorHTTPFixture(t, oidc.WorkloadTrust{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: oidc.GitHubIssuer + "/.well-known/jwks", Claims: map[string]string{"sub": "repo:example/repository:ref:refs/heads/main", "repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main", "environment": "ci", "job_workflow_ref": "example/shared/.github/workflows/reuse.yml@refs/tags/v1"}, Events: []string{"push"}}, map[string]controlv1.ServiceDefinitionService{"cluster": {Protocol: "kubernetes"}}, controlv1.EnvironmentTargets{"cluster": {Discovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Eks, Region: "us-east-1", Cluster: new("production")}}})
	ctx, d, server, team := t.Context(), f.database, f.server, f.team
	if f.environment.Targets["cluster"].Discovery == nil || f.environment.Targets["cluster"].Address != nil {
		t.Fatal("cloud selector did not survive environment creation")
	}
	job, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	claims := githubtest.Claims(server.URL, time.Now())
	claims["environment"], claims["job_workflow_ref"] = "ci", "example/shared/.github/workflows/reuse.yml@refs/tags/v1"
	assertion := f.issuer.Sign(t, claims)
	// provider metadata belongs to the verified source, not the narrowed native
	// visitor session. retain its signed execution assertions at that boundary.
	verifier, err := oidc.NewGitHubWorkloadVerifier(server.URL, f.issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	g, err := verifier.Verify(ctx, assertion)
	if err != nil || g.RepositoryID != "12345" || g.RepositoryOwnerID != "6789" || g.RunID != "111" || g.RunAttempt != "1" || g.CheckRunID != "222" {
		t.Fatal("verified GitHub source omitted signed execution metadata", err)
	}
	prepared, err := job.Prepare(ctx, f.environment.Ref, f.permission, assertion, f.services)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	var provider string
	var admitted []byte
	if err := f.inspect.QueryRow(ctx, `SELECT provider,claims FROM control.workload_sessions WHERE id=$1`, session.Id).Scan(&provider, &admitted); err != nil {
		t.Fatal("read the actual HTTP-admitted source identity", err)
	}
	var execution oidc.WorkloadExecution
	if err := json.Unmarshal(admitted, &execution); err != nil || provider != "github" || execution.GitHub == nil || execution.GitHub.RepositoryID != g.RepositoryID || execution.GitHub.RepositoryOwnerID != g.RepositoryOwnerID || execution.GitHub.RunID != g.RunID || execution.GitHub.RunAttempt != g.RunAttempt || execution.GitHub.CheckRunID != g.CheckRunID {
		t.Fatal("HTTP admission did not bind its session to the verified GitHub execution", err)
	}
	retry, err := job.Prepare(ctx, f.environment.Ref, f.permission, assertion, f.services)
	if err != nil || retry.Session.Id != session.Id || retry.Session.Credential != session.Credential || !retry.Session.ExpiresAt.Equal(*session.ExpiresAt) {
		t.Fatal("HTTP lost-reply recovery changed execution", err)
	}
	services, err := job.ListServices(ctx)
	if err != nil || len(services.Services) != 1 || services.Services[0].Protocol != controlv1.Kubernetes {
		t.Fatal("native visitor inventory", err)
	}
	service, hint := services.Services[0].Id, services.Services[0].KubernetesAuth
	if hint == nil || hint.Provider != controlv1.KubernetesEKS || hint.Cluster != "production" || hint.Region != "us-east-1" {
		t.Fatal("missing approved Kubernetes auth hint")
	}
	// environment management does not itself grant visitor inventory access.
	if ungranted, err := f.owner.ListAvailableServices(ctx); err != nil || len(ungranted) != 0 {
		t.Fatal("environment manager acquired visitor inventory without a grant", err)
	}
	if _, err := d.CreateServiceGrant(ctx, service, f.human.Identity.Identity.ID, "human-cluster-visitor", "identity", f.human.Identity.Identity.ID, nil, time.Now()); err != nil {
		t.Fatal("grant the human exact service visitor access", err)
	}
	humanServices, err := f.owner.ListAvailableServices(ctx)
	if err != nil || len(humanServices) != 1 || humanServices[0].KubernetesAuth == nil || *humanServices[0].KubernetesAuth != *hint {
		t.Fatal("human inventory lost approved auth hint", err)
	}
	if decision, err := job.CheckService(ctx, service); err != nil || decision.Subject.WorkloadSessionId == nil || *decision.Subject.WorkloadSessionId != session.Id {
		t.Fatal("native visitor authorization", err)
	}
	if _, err := job.ServiceClientCertificate(ctx, service); err != nil {
		t.Fatal("visitor public-path certificate", err)
	}
	if certificate, err := job.ClientTLSCertificate(ctx, service); err != nil || certificate.PrivateKey == nil || certificate.Leaf == nil {
		t.Fatal("native visitor TLS adapter", err)
	}
	t.Run("connector peer pair", func(t *testing.T) {
		exerciseWorkloadConnectorPeerPair(t, d, job, server, f.human, team, f.environment, service, session.Credential, f.databaseURL)
		if t.Failed() {
			return
		}
		t.Run("uncapped rebinding", func(t *testing.T) {
			uncapped, err := workload.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			permission := f.issuePermission(t, []string{"cluster"}, 0)
			current, err := uncapped.Prepare(t.Context(), f.environment.Ref, permission, assertion, f.services)
			if err != nil || current.Session.ExpiresAt != nil {
				t.Fatal("uncapped session acquired hard limit", err)
			}
			exerciseUncappedWorkloadConnectorRebind(t, uncapped, service, f.databaseURL)
		})
	})
	if t.Failed() {
		return
	}
	if renewed, err := job.Renew(ctx); err != nil || !renewed.ExpiresAt.Equal(*session.ExpiresAt) || !renewed.LeaseExpiresAt.Equal(session.LeaseExpiresAt) {
		t.Fatal("early renewal extended execution", err)
	}
	t.Run("renewal proof HTTP boundary", func(t *testing.T) {
		current, err := job.Session()
		if err != nil {
			t.Fatal(err)
		}
		sequence := current.RenewalSequence + 1
		proof := authorityv1.EnvironmentVisitorRenewal{Sequence: sequence, Signature: base64.RawURLEncoding.EncodeToString(job.Sign(workloadproof.Renew(current.Id, sequence)))}
		encoded, _ := json.Marshal(proof)
		_, otherKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrongKey := proof
		wrongKey.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherKey, workloadproof.Renew(current.Id, sequence)))
		wrongBody, _ := json.Marshal(wrongKey)
		for _, test := range []struct {
			body   string
			status int
		}{
			{"", 400}, {"null", 400}, {"{}", 400},
			{`{"sequence":0,"signature":"` + proof.Signature + `"}`, 400},
			{`{"sequence":9223372036854775808,"signature":"` + proof.Signature + `"}`, 400},
			{`{"sequence":2,"signature":"invalid"}`, 400},
			{string(encoded) + ` {}`, 400}, {strings.Repeat(" ", 65<<10) + string(encoded), 400},
			{string(wrongBody), 403}, {`{"sequence":3,"signature":"` + proof.Signature + `"}`, 403},
			{`{"sequence":2,"signature":"` + base64.RawURLEncoding.EncodeToString(job.Sign(workloadproof.Renew("other", sequence))) + `"}`, 403},
			{string(encoded), 200}, {string(encoded), 200},
		} {
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/environment-visitor-sessions/"+current.Id+"/renew", strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+current.Credential)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected renewal response", response.StatusCode, test.status, err)
			}
			if response.StatusCode != 200 {
				if bytes.Contains(data, []byte(current.Credential)) || bytes.Contains(data, []byte(proof.Signature)) {
					t.Fatal("renewal error exposed private proof")
				}
				continue
			}
			var renewed authorityv1.EnvironmentVisitorSession
			if err := json.Unmarshal(data, &renewed); err != nil || renewed.RenewalSequence != sequence || !renewed.LeaseExpiresAt.Equal(current.LeaseExpiresAt) || !renewed.ExpiresAt.Equal(*current.ExpiresAt) {
				t.Fatal("early renewal or retry changed lease", err)
			}
		}
		if renewed, err := job.Renew(ctx); err != nil || renewed.RenewalSequence != sequence {
			t.Fatal("native retry did not recover committed renewal", err)
		}
	})
	for _, bad := range []struct {
		field string
		value any
	}{{"repository_id", "999"}, {"repository_owner_id", "999"}, {"environment", "production"}, {"job_workflow_ref", "example/shared/.github/workflows/reuse.yml@refs/tags/v2"}, {"ref", "refs/heads/other"}, {"event_name", "pull_request"}, {"run_id", "not-a-run-id"}, {"check_run_id", nil}} {
		mutated := githubtest.Claims(server.URL, time.Now())
		mutated["environment"], mutated["job_workflow_ref"] = claims["environment"], claims["job_workflow_ref"]
		mutated[bad.field] = bad.value
		if _, err := job.Prepare(ctx, f.environment.Ref, f.permission, f.issuer.Sign(t, mutated), f.services); err == nil {
			t.Fatalf("HTTP accepted wrong %s", bad.field)
		}
	}
	visitorControl, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitorControl.ApplyEnvironment(ctx, "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: team, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision}); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("visitor self-applied environment", err)
	}
	if _, err := visitorControl.GetEnvironment(ctx, team, "example", f.environment.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("visitor read manager targets", err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.IdentityContext(ctx); !errors.Is(err, clientauthority.ErrUnauthenticated) {
		t.Fatal("visitor became human session", err)
	}
	if _, err := visitorControl.GetEnvironmentPublisherAssignments(ctx, session.Credential); err == nil {
		t.Fatal("visitor became publisher")
	}
	for _, path := range []string{"/v1/workload/services", "/v1/identity"} {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		r.Header.Set("Authorization", "Bearer "+session.Credential)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(assertion)) || bytes.Contains(data, []byte("target_discovery")) || bytes.Contains(data, []byte(session.Credential)) {
			t.Fatal("visitor response leaked credential or target")
		}
	}
	if err := job.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := job.CheckService(ctx, service); err == nil {
		t.Fatal("revoked visitor retained access")
	}
	if _, err := f.owner.GetEnvironment(ctx, team, "example", f.environment.Id); err != nil {
		t.Fatal("visitor revoke affected manager", err)
	}
	t.Run("retained and collected deletion ownership", func(t *testing.T) {
		requestStatus := func(method, path, credential string, want int) {
			t.Helper()
			var body io.Reader
			if strings.HasSuffix(path, "/renew") {
				body = strings.NewReader(`{"sequence":1,"signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `"}`)
			}
			r, err := http.NewRequestWithContext(ctx, method, server.URL+path, body)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "Bearer "+credential)
			r.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != want {
				t.Fatal(method, path, response.StatusCode, want, err)
			}
			if bytes.Contains(data, []byte(credential)) {
				t.Fatal("deletion response exposed bearer")
			}
		}
		for i, name := range []string{"lease-expired", "old-expired", "old-revoked"} {
			other, err := workload.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			created, err := other.Prepare(ctx, f.environment.Ref, f.permission, assertion, f.services)
			if err != nil {
				t.Fatal(err)
			}
			s := created.Session
			at := time.Now().Add(-40 * 24 * time.Hour)
			if i == 0 {
				at = time.Now().Add(-2 * time.Minute)
			}
			// age only the real admitted session's clocks and receipt history;
			// cleanup must also observe the original source proof's expiry.
			if _, err := f.inspect.Exec(ctx, `UPDATE control.workload_sessions SET created_at=$2::timestamptz,renewed_at=$2::timestamptz,lease_expires_at=$2::timestamptz+interval '90 seconds',identity_expires_at=$2::timestamptz+interval '5 minutes',expires_at=$2::timestamptz+interval '1 hour',claims=claims||jsonb_build_object('iat',extract(epoch FROM $2::timestamptz)::bigint,'nbf',extract(epoch FROM $2::timestamptz)::bigint,'exp',extract(epoch FROM $2::timestamptz+interval '5 minutes')::bigint) WHERE id=$1`, s.Id, at); err != nil {
				t.Fatal(err)
			}
			if _, err := f.inspect.Exec(ctx, `UPDATE control.workload_audit SET occurred_at=$2 WHERE workload_session_id=$1`, s.Id, at); err != nil {
				t.Fatal(err)
			}
			if name == "old-revoked" {
				if err := d.RevokeEnvironmentVisitorSession(ctx, s.Id, s.Credential, at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			path := "/v1/environment-visitor-sessions/" + s.Id
			renewStatus := http.StatusForbidden
			if name == "old-expired" {
				renewStatus = http.StatusGone
			}
			for range 2 {
				requestStatus("DELETE", path, session.Credential, 403)
				if name != "old-expired" {
					requestStatus("DELETE", path, s.Credential, 204)
				}
				requestStatus("POST", path+"/renew", s.Credential, renewStatus)
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
				requestStatus("DELETE", path, s.Credential, 403)
				requestStatus("POST", path+"/renew", s.Credential, 403)
			}
		}
	})
	for _, path := range []string{"/v1/workload-sessions/exchange", "/v1/workload-sessions/identity", "/v1/workload-sessions/" + session.Id + "/assertions"} {
		assertRetainedHTTPRemoved(t, server.Client(), server.URL, session.Credential, http.MethodPost, path)
	}
}
