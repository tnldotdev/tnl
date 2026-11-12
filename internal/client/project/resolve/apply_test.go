package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type environmentBackend struct {
	definitions  []controlv1.ServiceDefinition
	environments map[string]controlv1.Environment
	calls        []string
	fail         error
	collections  []controlv1.Collection
	creation     *controlv1.CreateEnvironmentRequest
}

func (b *environmentBackend) CreateServiceDefinition(_ context.Context, project string, r controlv1.CreateServiceDefinitionRequest) (controlv1.ServiceDefinitionRevision, error) {
	b.calls = append(b.calls, "definition")
	if b.fail != nil {
		return controlv1.ServiceDefinitionRevision{}, b.fail
	}
	b.definitions = append(b.definitions, r.Definition)
	return controlv1.ServiceDefinitionRevision{TeamId: r.TeamId, ProjectKey: project, SourceFingerprint: r.SourceFingerprint, Revision: int64(len(b.definitions)), Definition: r.Definition}, nil
}
func (b *environmentBackend) ListEnvironments(_ context.Context, _, _ string) ([]controlv1.Environment, error) {
	b.calls = append(b.calls, "list")
	result := []controlv1.Environment{}
	for _, value := range b.environments {
		result = append(result, value)
	}
	return result, nil
}
func (b *environmentBackend) CreateEnvironment(_ context.Context, project string, r controlv1.CreateEnvironmentRequest) (controlv1.Environment, error) {
	b.calls = append(b.calls, "create:"+r.Name)
	if r.IdempotencyKey == "" {
		return controlv1.Environment{}, errors.New("missing idempotency key")
	}
	b.creation = &r
	value := controlv1.Environment{Id: r.Name + "-id", TeamId: r.TeamId, ProjectKey: project, Name: r.Name, AppliedDefinitionRevision: *r.DefinitionRevision, MutationRevision: 1, Targets: r.Targets, CollectionId: r.CollectionId}
	b.environments[value.Id] = value
	return value, nil
}
func (b *environmentBackend) ApplyEnvironment(_ context.Context, _ string, id string, r controlv1.ApplyEnvironmentRequest) (controlv1.Environment, error) {
	b.calls = append(b.calls, "apply:"+id)
	value := b.environments[id]
	if value.MutationRevision != r.ExpectedRevision || r.Targets == nil {
		return controlv1.Environment{}, errors.New("missing revision fence or explicit targets")
	}
	value.MutationRevision++
	value.AppliedDefinitionRevision, value.Targets = r.DefinitionRevision, *r.Targets
	b.environments[id] = value
	return value, nil
}
func (b *environmentBackend) ListCollections(context.Context, string, string) ([]controlv1.Collection, error) {
	b.calls = append(b.calls, "collections")
	return b.collections, nil
}
func (b *environmentBackend) CreateCollection(_ context.Context, project string, r controlv1.CreateCollectionRequest) (controlv1.Collection, error) {
	b.calls = append(b.calls, "create-collection")
	collection := controlv1.Collection{CollectionId: "collection-id", TeamId: r.TeamId, ProjectKey: project, Name: r.Name, DefaultDefinitionRevision: r.DefaultDefinitionRevision, MutationRevision: 1}
	b.collections = append(b.collections, collection)
	return collection, nil
}

func (b *environmentBackend) UpdateCollectionDefault(_ context.Context, _ string, id string, r controlv1.UpdateCollectionDefaultRequest) (controlv1.Collection, error) {
	b.calls = append(b.calls, "collection-default")
	for i, value := range b.collections {
		if value.CollectionId != id {
			continue
		}
		if value.MutationRevision != r.ExpectedRevision {
			return controlv1.Collection{}, errors.New("missing collection mutation fence")
		}
		value.MutationRevision++
		value.DefaultDefinitionRevision = r.DefinitionRevision
		b.collections[i] = value
		return value, nil
	}
	return controlv1.Collection{}, errors.New("collection not found")
}

func applyProject(t *testing.T) clientproject.Project {
	t.Helper()
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", "https://github.com/example/project.git"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v: %s", err, output)
		}
	}
	return clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: clientproject.Worktree{IsGit: true, Root: root}, Config: config.TNL{
		Services: config.Services{"database": {Protocol: new("postgres")}},
		Environments: map[string]config.Environment{
			"local":      {Targets: map[string]config.EnvironmentTarget{"database": {Address: new(config.Target("127.0.0.1:5432"))}}},
			"staging":    {Targets: map[string]config.EnvironmentTarget{"database": {Address: new(config.Target("db.staging.internal:5432")), TLS: &config.EnvironmentTargetTLS{}}}},
			"production": {Targets: map[string]config.EnvironmentTarget{"database": {Address: new(config.Target("db.production.internal:5432")), TLS: &config.EnvironmentTargetTLS{}}}},
		},
	}}
}

func TestApplyEnvironmentPublishesShapeAndMutatesOnlySelectedEnvironment(t *testing.T) {
	project := applyProject(t)
	backend := &environmentBackend{environments: map[string]controlv1.Environment{}}
	staging, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "stage-key")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(staging)
	production, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "production", "production-key")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(backend.environments[staging.Id])
	if string(before) != string(after) {
		t.Fatal("production apply mutated staging")
	}
	if *production.Targets["database"].Address != "db.production.internal:5432" || *staging.Targets["database"].Address != "db.staging.internal:5432" || staging.Targets["database"].Tls == nil || *staging.Targets["database"].Tls.Hostname != "db.staging.internal" {
		t.Fatal("apply crossed target/trust boundaries")
	}
	updated, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "stage-retry")
	if err != nil || updated.Id != staging.Id || updated.MutationRevision != staging.MutationRevision+1 {
		t.Fatalf("saved identity or mutation fence changed: %+v: %v", updated, err)
	}
	for _, definition := range backend.definitions {
		encoded, _ := json.Marshal(definition)
		if string(encoded) != `{"services":{"database":{"protocol":"postgres"}}}` {
			t.Fatalf("definition contains environment authority: %s", encoded)
		}
	}
	if !reflect.DeepEqual(backend.calls, []string{"list", "definition", "create:staging", "list", "definition", "create:production", "list", "definition", "apply:staging-id"}) {
		t.Fatalf("apply order: %v", backend.calls)
	}
}

func TestApplyEnvironmentFailsClosedBeforeMutations(t *testing.T) {
	for _, name := range []string{"missing", "local"} {
		t.Run(name, func(t *testing.T) {
			project := applyProject(t)
			backend := &environmentBackend{}
			if _, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), name, "key"); err == nil || len(backend.calls) != 0 {
				t.Fatalf("unsupported selection mutated control: %v, %v", backend.calls, err)
			}
		})
	}
	project := applyProject(t)
	cause := errors.New("definition publish failed")
	backend := &environmentBackend{environments: map[string]controlv1.Environment{}, fail: cause}
	if _, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "key"); !errors.Is(err, cause) || !reflect.DeepEqual(backend.calls, []string{"list", "definition"}) {
		t.Fatalf("failed definition reached environment mutation: %v, %v", backend.calls, err)
	}
}

func TestApplyEnvironmentIgnoresWorkloadAuthorityIntent(t *testing.T) {
	project := applyProject(t)
	environment := project.Config.Environments["staging"]
	environment.Workloads = map[string]config.Workload{"accounts": {Vercel: &config.WorkloadVercel{Project: "accounts", Environment: "production"}, Services: []string{"database"}}}
	project.Config.Environments["staging"] = environment
	backend := &environmentBackend{environments: map[string]controlv1.Environment{}}
	for range 2 {
		if _, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "key"); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(backend.calls, []string{"list", "definition", "create:staging", "list", "definition", "apply:staging-id"}) {
		t.Fatalf("apply consulted workload authority: %v", backend.calls)
	}
	for _, definition := range backend.definitions {
		data, _ := json.Marshal(definition)
		if string(data) != `{"services":{"database":{"protocol":"postgres"}}}` {
			t.Fatalf("definition contains authority: %s", data)
		}
	}
}

func TestApplyEnvironmentRetainsCollectionDefaultAndImmutableMembership(t *testing.T) {
	project := applyProject(t)
	project.Config.Collections = map[string]config.Collection{"customers": {}, "other": {}}
	staging := project.Config.Environments["staging"]
	staging.Collection = new("customers")
	project.Config.Environments["staging"] = staging
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	collection := controlv1.Collection{CollectionId: "customers-id", TeamId: appliedTestContext().Team().Id, ProjectKey: source.Key, Name: "customers", DefaultDefinitionRevision: 99, MutationRevision: 7}
	backend := &environmentBackend{environments: map[string]controlv1.Environment{}, collections: []controlv1.Collection{collection}}
	if _, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "key"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(backend.collections, []controlv1.Collection{collection}) || backend.creation.CollectionId == nil || *backend.creation.CollectionId != collection.CollectionId || *backend.creation.ExpectedCollectionRevision != collection.MutationRevision {
		t.Fatal("member apply changed a collection default or omitted its creation fence")
	}
	staging.Collection = new("other")
	project.Config.Environments["staging"] = staging
	before := len(backend.definitions)
	if _, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "key"); err == nil || len(backend.definitions) != before {
		t.Fatal("apply moved immutable collection membership or published before checking it")
	}
}

func TestApplyCollectionDefaultDoesNotApplyExistingMembers(t *testing.T) {
	project := applyProject(t)
	project.Config.Collections = map[string]config.Collection{"customers": {}}
	backend := &environmentBackend{environments: map[string]controlv1.Environment{}}
	staging, err := ApplyEnvironment(t.Context(), backend, project, appliedTestContext(), "staging", "key")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(staging)
	collection, err := ApplyCollection(t.Context(), backend, project, appliedTestContext().Team().Id, "customers")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ApplyCollection(t.Context(), backend, project, appliedTestContext().Team().Id, "customers")
	if err != nil || updated.CollectionId != collection.CollectionId || updated.MutationRevision != collection.MutationRevision+1 || updated.DefaultDefinitionRevision <= collection.DefaultDefinitionRevision {
		t.Fatalf("collection default fence: %+v, %v", updated, err)
	}
	after, _ := json.Marshal(backend.environments[staging.Id])
	if string(before) != string(after) || !reflect.DeepEqual(backend.calls, []string{"list", "definition", "create:staging", "collections", "definition", "create-collection", "collections", "definition", "collection-default"}) {
		t.Fatalf("collection apply reconciled installed members: %v", backend.calls)
	}
}
