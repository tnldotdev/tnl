package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationMachineEnvironmentVisitorCollectionScopes(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, _ := f.register(t, "oidc")
	permissions := map[string]string{
		"exact":  f.permission(t, machine, machineEnvironmentScope(f.environment.ID)),
		"fixed":  f.permission(t, machine, authorityv1.EnvironmentPermissionScope{CollectionId: new(f.collection.ID), IncludeFutureEnvironments: new(false)}),
		"future": f.permission(t, machine, authorityv1.EnvironmentPermissionScope{CollectionId: new(f.collection.ID), IncludeFutureEnvironments: new(true)}),
	}
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	third, err := f.d.CreateEnvironment(t.Context(), controlstate.CreateEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor,
		SourceFingerprint: strings.Repeat("a", 64), Name: "third", CollectionID: f.collection.ID, ExpectedCollectionRevision: f.collection.MutationRevision,
		IdempotencyKey: "create/third", Targets: f.environment.Targets, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	for name, permission := range permissions {
		for _, environment := range []controlstate.Environment{f.environment, f.otherEnvironment, third} {
			body := f.prepareBody(t, permission, environment.ID, "prepare", rand.Text(), machine, nil, ephemeral)
			r, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", environment.ID, body)
			if err != nil {
				t.Fatal(err)
			}
			allowed := name == "future" || name == "fixed" && environment.ID != third.ID || name == "exact" && environment.ID == f.environment.ID
			if allowed && r.JSON200 == nil || !allowed && r.StatusCode() != 403 {
				t.Fatal("scope did not preserve captured membership", name, environment.Name, r.StatusCode())
			}
		}
	}
	// a future-environment grant never captures future service names. changing a
	// collection default applies only to later environments, not current members.
	definition, err := f.d.CreateServiceDefinition(t.Context(), controlstate.CreateServiceDefinitionRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor,
		SourceFingerprint: strings.Repeat("a", 64), Definition: controlstate.ServiceDefinition{Services: map[string]controlstate.ServiceDefinitionService{"api": {Protocol: "http"}, "secret": {Protocol: "tcp"}, "metrics": {Protocol: "http"}}}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	updatedCollection, err := f.d.UpdateCollectionDefault(t.Context(), controlstate.UpdateCollectionDefaultRequest{TeamID: f.team, ProjectKey: "equipment", CollectionID: f.collection.ID, ActorID: f.actor,
		ExpectedRevision: f.collection.MutationRevision, DefinitionRevision: definition.Revision, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	later, err := f.d.CreateEnvironment(t.Context(), controlstate.CreateEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor,
		SourceFingerprint: strings.Repeat("a", 64), Name: "later", CollectionID: f.collection.ID, ExpectedCollectionRevision: updatedCollection.MutationRevision, IdempotencyKey: "create/later",
		Targets: controlstate.EnvironmentTargets{"api": {Address: "api.internal:3000"}, "secret": {Address: "secret.internal:22"}, "metrics": {Address: "metrics.internal:9090"}}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.d.GetEnvironment(t.Context(), f.team, "equipment", f.environment.ID, f.actor)
	if err != nil || current.AppliedDefinitionRevision != f.environment.AppliedDefinitionRevision || current.MutationRevision != f.environment.MutationRevision || current.ConfigurationHash != f.environment.ConfigurationHash {
		t.Fatal("collection default mutated an existing environment", err)
	}
	body := f.prepareBody(t, permissions["future"], later.ID, "prepare", rand.Text(), machine, nil, ephemeral)
	r, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", later.ID, body)
	if err != nil || r.JSON200 == nil || len(r.JSON200.Services) != 1 {
		t.Fatal("future member did not keep its explicit service scope", err)
	}
	body.Services = map[string]controlv1.ServiceProtocol{"api": "http", "metrics": "http"}
	digest := sha256.Sum256([]byte(body.Assertion))
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permissions["future"], later.ID, "prepare", body.PublicKey, body.Nonce, map[string]string{"api": "http", "metrics": "http"}, digest)))
	denied, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", later.ID, body)
	if err != nil {
		t.Fatal("future service scope request failed without a response", err)
	}
	if denied.StatusCode() != 403 {
		t.Fatalf("future service scope returned HTTP %d, want 403", denied.StatusCode())
	}
	if err := f.d.RetireEnvironment(t.Context(), controlstate.RetireEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", EnvironmentID: later.ID, ActorID: f.actor, ExpectedRevision: later.MutationRevision, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	body = f.prepareBody(t, permissions["future"], later.ID, "prepare", rand.Text(), machine, nil, ephemeral)
	denied, err = f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", later.ID, body)
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("future scope restored a retired environment", err)
	}
}
