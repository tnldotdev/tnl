package workloadsetup

import (
	"context"
	"errors"
	"maps"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/githubmetadata"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type approvalBackend struct {
	result            *authorityv1.WorkloadApproval
	machine           *authorityv1.MachineIdentity
	readErr, writeErr error
	gets, puts, lists int
	environment       controlv1.Environment
}

func (b *approvalBackend) GetWorkloadApproval(context.Context, string, string) (authorityv1.WorkloadApproval, error) {
	b.gets++
	if b.readErr != nil {
		return authorityv1.WorkloadApproval{}, b.readErr
	}
	if b.result == nil {
		return authorityv1.WorkloadApproval{}, clientauthority.ErrNotFound
	}
	return *b.result, nil
}
func (b *approvalBackend) ApproveWorkload(_ context.Context, team, intent string, r authorityv1.WorkloadApprovalRequest) (authorityv1.WorkloadApproval, error) {
	b.puts++
	result := authorityv1.WorkloadApproval{IntentKey: intent, Request: r, CreatedAt: time.Now(), Machine: authorityv1.MachineIdentity{Id: "mci_" + strings.Repeat("a", 22), TeamId: team, Name: r.Workload, ProofKind: "oidc", Trust: &r.Trust, Revision: 1}, Selection: authorityv1.IdentitySourceVisitorSelection{Environment: controlv1.EnvironmentReference{Server: "https://control.example", ProjectKey: r.ProjectKey, EnvironmentId: r.EnvironmentId}, PermissionId: "mwp_" + strings.Repeat("b", 22), Services: map[string]controlv1.ServiceProtocol{"api": "http"}}}
	if b.machine != nil {
		result.Machine = *b.machine
	}
	b.result = &result
	return result, b.writeErr
}
func (b *approvalBackend) ListEnvironments(context.Context, string, string) ([]controlv1.Environment, error) {
	b.lists++
	return []controlv1.Environment{b.environment}, nil
}

func approvalOptions(t *testing.T) (ApprovalOptions, *approvalBackend) {
	t.Helper()
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", "https://github.com/example/project.git"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %s, %v", data, err)
		}
	}
	project := clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: clientproject.Worktree{IsGit: true, Root: root}, Config: config.TNL{Services: config.Services{"api": {}}, Environments: map[string]config.Environment{"staging": {Workloads: map[string]config.Workload{"tests": {OIDC: &config.WorkloadOIDC{Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Claims: map[string]string{"sub": "test-job"}}, Services: []string{"api"}}}}}}}
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	o := ApprovalOptions{Project: project, Server: "https://control.example", TeamID: "team", Environment: "staging", Workload: "tests", Intent: "approve-1", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	b := &approvalBackend{environment: controlv1.Environment{Id: "env_" + strings.Repeat("c", 22), Name: "staging", TeamId: o.TeamID, ProjectKey: source.Key, AppliedDefinitionRevision: 2, MutationRevision: 5, Services: []controlv1.EnvironmentService{{Service: "api", Protocol: "http"}}}}
	return o, b
}

func TestApprovalRecoversLostReplyWithoutProviderOrEnvironmentResolution(t *testing.T) {
	o, b := approvalOptions(t)
	lost := errors.New("response lost after commit")
	b.writeErr = lost
	binds := 0
	bind := func(ctx context.Context, o Options) (map[string]controlv1.ProjectWorkload, error) {
		binds++
		return Resolve(ctx, o)
	}
	if _, err := approve(t.Context(), b, b, o, bind); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	first := *b.result
	b.environment = controlv1.Environment{}
	for _, state := range []string{"active", "revoked", "expired"} {
		if state == "revoked" {
			b.result.PermissionRevokedAt = new(time.Now())
		}
		if state == "expired" {
			o.ExpiresAt = time.Now().Add(-time.Hour)
			b.result.Request.ExpiresAt = o.ExpiresAt
		}
		recovered, err := approve(t.Context(), b, b, o, func(context.Context, Options) (map[string]controlv1.ProjectWorkload, error) {
			t.Fatal("recovery contacted provider")
			return nil, nil
		})
		if err != nil || recovered.Machine.Id != first.Machine.Id || recovered.Selection.PermissionId != first.Selection.PermissionId {
			t.Fatalf("%s recovery: %+v, %v", state, recovered, err)
		}
	}
	if binds != 1 || b.puts != 1 || b.lists != 1 {
		t.Fatalf("recovery ran creation: %+v, binds=%d", b, binds)
	}
}

func TestApprovalFailsClosedOnReadAndScopeMismatch(t *testing.T) {
	for _, change := range []string{"read", "intent", "team", "server", "environment", "machine", "permission", "services", "duration", "declaration", "expiry"} {
		t.Run(change, func(t *testing.T) {
			o, b := approvalOptions(t)
			if _, err := Approve(t.Context(), b, b, o); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "read":
				b.readErr = errors.New("not authorized")
			case "intent":
				b.result.IntentKey = "another"
			case "team":
				b.result.Machine.TeamId = "another"
			case "server":
				b.result.Selection.Environment.Server = "https://other.example"
			case "environment":
				b.result.Selection.Environment.EnvironmentId = "env_" + strings.Repeat("d", 22)
			case "machine":
				b.result.Machine.Id = "not-a-machine"
			case "permission":
				b.result.Selection.PermissionId = "not-a-permission"
			case "services":
				b.result.Request.Services = []string{"secret"}
			case "duration":
				b.result.Request.MaxDurationSeconds++
			case "declaration":
				e := o.Project.Config.Environments[o.Environment]
				w := e.Workloads[o.Workload]
				w.OIDC.Claims["sub"] = "changed"
				e.Workloads[o.Workload] = w
			case "expiry":
				o.ExpiresAt = o.ExpiresAt.Add(time.Minute)
			}
			if _, err := approve(t.Context(), b, b, o, func(context.Context, Options) (map[string]controlv1.ProjectWorkload, error) {
				t.Fatal("invalid recovery contacted provider")
				return nil, nil
			}); err == nil {
				t.Fatal("invalid recovery accepted")
			}
			if b.puts != 1 || b.lists != 1 {
				t.Fatal("invalid recovery created replacement authority")
			}
		})
	}
}

func TestApprovalRequiresAppliedProtocolsAndExplicitIntent(t *testing.T) {
	for _, change := range []string{"intent", "expiry", "environment", "protocol"} {
		t.Run(change, func(t *testing.T) {
			o, b := approvalOptions(t)
			switch change {
			case "intent":
				o.Intent = ""
			case "expiry":
				o.ExpiresAt = time.Time{}
			case "environment":
				o.Environment = "local"
			case "protocol":
				b.environment.Services[0].Protocol = "tcp"
			}
			if _, err := approve(t.Context(), b, b, o, func(context.Context, Options) (map[string]controlv1.ProjectWorkload, error) {
				t.Fatal("invalid approval contacted provider")
				return nil, nil
			}); err == nil || b.puts != 0 {
				t.Fatal("approval ignored explicit scope")
			}
		})
	}
}

func TestApprovalGitHubTrustKeepsProviderAndExecutionPolicy(t *testing.T) {
	bound := controlv1.ProjectWorkload{Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"workflow_dispatch", "push"}, Environment: new("staging"), JobWorkflowRef: new("example/reusable/.github/workflows/test.yml@refs/heads/main")}}
	trust, err := approvalTrust(bound, "https://control.example")
	if err != nil || trust.Provider != "github" || trust.Audience != "https://control.example" || trust.Claims["repository_id"] != "12345" || trust.Claims["workflow_ref"] != bound.Github.WorkflowRef || trust.Claims["job_workflow_ref"] != *bound.Github.JobWorkflowRef || trust.Claims["environment"] != "staging" || trust.Events == nil || len(*trust.Events) != 2 {
		t.Fatalf("provider authority lost in conversion: %+v, %v", trust, err)
	}
}

func TestApprovalGitHubEventOrderFirstApprovalAndRecovery(t *testing.T) {
	o, b := approvalOptions(t)
	environment := o.Project.Config.Environments[o.Environment]
	environment.Workloads[o.Workload] = config.Workload{GitHub: &config.WorkloadGitHub{Repository: new("example/repository"), Workflow: ".github/workflows/test.yml", Branch: new("main"), Events: []string{"workflow_dispatch", "push"}}, Services: []string{"api"}}
	o.Project.Config.Environments[o.Environment] = environment
	registered := authorityv1.MachineTrust{Provider: authorityv1.MachineTrustGitHub, Issuer: "https://token.actions.githubusercontent.com", JwksUrl: "https://token.actions.githubusercontent.com/.well-known/jwks", Audience: o.Server, Claims: map[string]string{"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main"}, Events: new([]string{"workflow_dispatch", "push"})}
	b.machine = &authorityv1.MachineIdentity{Id: "mci_" + strings.Repeat("r", 22), TeamId: o.TeamID, Name: "previous-registration", ProofKind: "oidc", Trust: &registered, Revision: 7}
	resolver := newResolver()
	providerCalls := 0
	resolver.github = func(context.Context, string) (githubmetadata.Repository, error) {
		providerCalls++
		return githubmetadata.Repository{Repository: "example/repository", RepositoryID: "12345", OwnerID: "6789", DefaultBranch: "main"}, nil
	}
	first, err := approve(t.Context(), b, b, o, resolver.resolve)
	if err != nil {
		t.Fatal("first approval rejected the registered event set", err)
	}
	if first.Machine.Id != b.machine.Id || first.Machine.Revision != 7 || first.Selection.PermissionId != "mwp_"+strings.Repeat("b", 22) {
		t.Fatal("first approval replaced saved machine or permission IDs", first)
	}
	if reflect.DeepEqual(*first.Machine.Trust, first.Request.Trust) || !slices.Equal(*first.Machine.Trust.Events, []string{"workflow_dispatch", "push"}) || !slices.Equal(*first.Request.Trust.Events, []string{"push", "workflow_dispatch"}) {
		t.Fatal("fixture did not retain distinct event order in machine and request", first)
	}
	b.environment = controlv1.Environment{}
	noProvider := func(context.Context, Options) (map[string]controlv1.ProjectWorkload, error) {
		t.Fatal("receipt recovery contacted the provider")
		return nil, nil
	}
	recovered, err := approve(t.Context(), b, b, o, noProvider)
	if err != nil || !reflect.DeepEqual(recovered, first) {
		t.Fatalf("same-intent recovery changed the receipt: %+v, %v", recovered, err)
	}
	if b.gets != 2 || b.puts != 1 || b.lists != 1 || providerCalls != 1 {
		t.Fatalf("recovery repeated approval or resolution: gets=%d puts=%d lists=%d provider=%d", b.gets, b.puts, b.lists, providerCalls)
	}
	for _, change := range []string{"event membership", "events omitted", "duplicate event", "provider", "issuer", "jwks", "audience", "claim value", "claim omitted", "extra claim"} {
		t.Run(change, func(t *testing.T) {
			changed := registered
			changed.Claims = maps.Clone(registered.Claims)
			changed.Events = new(slices.Clone(*registered.Events))
			switch change {
			case "event membership":
				changed.Events = new([]string{"push", "pull_request"})
			case "events omitted":
				changed.Events = nil
			case "duplicate event":
				changed.Events = new([]string{"push", "workflow_dispatch", "push"})
			case "provider":
				changed.Provider = authorityv1.MachineTrustOIDC
			case "issuer":
				changed.Issuer = "https://other.example"
			case "jwks":
				changed.JwksUrl = "https://other.example/keys"
			case "audience":
				changed.Audience = "another-audience"
			case "claim value":
				changed.Claims["repository_id"] = "99999"
			case "claim omitted":
				delete(changed.Claims, "repository_owner_id")
			case "extra claim":
				changed.Claims["environment"] = "production"
			}
			invalid := first
			invalid.Machine.Trust = &changed
			b.result = &invalid
			_, err := approve(t.Context(), b, b, o, noProvider)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("recovery accepted changed trust", err)
			}
			if b.puts != 1 || b.lists != 1 || providerCalls != 1 {
				t.Fatal("changed trust created replacement authority or contacted a provider")
			}
		})
	}
	if !slices.Equal(*registered.Events, []string{"workflow_dispatch", "push"}) || !slices.Equal(*first.Request.Trust.Events, []string{"push", "workflow_dispatch"}) {
		t.Fatal("trust comparison mutated saved event order")
	}
}

func TestApprovalTrustRetainsProviderQualifiedStableIdentity(t *testing.T) {
	for _, provider := range []controlv1.WorkloadProvider{controlv1.WorkloadGoogle, controlv1.WorkloadKubernetes, controlv1.WorkloadGitLab, controlv1.WorkloadVercel, controlv1.WorkloadFly, controlv1.WorkloadOIDC} {
		t.Run(string(provider), func(t *testing.T) {
			claims := map[string]string{"sub": "exact-subject", "service_account_uid": "exact-account-uid", "job_project_id": "12345", "job_namespace_id": "6789"}
			bound := controlv1.ProjectWorkload{Provider: provider, Trust: controlv1.WorkloadTrust{Provider: provider, Issuer: "https://issuer.example", JwksUrl: "https://issuer.example/keys", Audience: "https://control.example", Claims: claims}}
			trust, err := approvalTrust(bound, "https://control.example")
			if err != nil || string(trust.Provider) != string(provider) || !reflect.DeepEqual(trust.Claims, claims) {
				t.Fatalf("approval lost provider or stable identity: %+v, %v", trust, err)
			}
			if provider != controlv1.WorkloadOIDC {
				bound.Trust.Provider = controlv1.WorkloadOIDC
				if _, err := approvalTrust(bound, "https://control.example"); err == nil {
					t.Fatal("provider-specific approval downgraded to generic OIDC")
				}
			}
		})
	}
}
