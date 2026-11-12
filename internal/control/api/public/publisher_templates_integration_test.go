package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherGroupTemplateHTTP(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	definitionReply, err := f.client.CreateServiceDefinitionWithResponse(t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"diagnostics": {Protocol: "http"}}}})
	if err != nil || definitionReply.JSON200 == nil {
		t.Fatal("save reusable service definition", err)
	}
	definition := *definitionReply.JSON200
	collection := createCollectionHTTP(t, f, "tractors", definition.Revision)
	before, err := f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || before.JSON200 == nil || len(*before.JSON200) != 0 {
		t.Fatal("definition became a concrete environment", err)
	}
	request := collectionHTTPEnvironmentRequest(f, collection, "tractor-042", "localhost", "9080")
	request.Targets = controlv1.EnvironmentTargets{"diagnostics": {Address: new("http://localhost:9080")}}
	created := createCollectionHTTPEnvironment(t, f, request)
	if created.Name != "tractor-042" || created.Ref.Server != "https://control.example.test" || created.Ref.EnvironmentId != created.Id || len(created.Services) != 1 || created.Services[0].ServiceId == "" || created.Services[0].Service != "diagnostics" || created.Services[0].Protocol != "http" {
		t.Fatal("wrong saved environment descriptor")
	}
	// exercise the actual visitor boundary for this instantiated environment;
	// selecting a reference from manager targets is not visitor discovery.
	const server = "https://control.example.test"
	mux := http.NewServeMux()
	if _, err := controlauthority.Register(mux, controlauthority.Config{ControlURL: server, Machines: f.database, Publications: f.database}, f.database); err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", f.transport.handler)
	f.transport.set(mux, "10.0.0.2:1234", "8.8.8.8")
	visitorAPI, err := authorityv1.NewClientWithResponses(server, authorityv1.WithHTTPClient(&http.Client{Transport: f.transport}))
	if err != nil {
		t.Fatal(err)
	}
	public, source, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := visitorAPI.RegisterMachineIdentityWithResponse(t.Context(), f.team, authorityv1.RegisterMachineRequest{Name: "tractor-reviewer", ProofKind: "signing_key", KeyId: new("first"), PublicKey: new(base64.RawURLEncoding.EncodeToString(public))}, retainedVisitorBearer(f.session.AccessToken.String()))
	if err != nil || machine.JSON201 == nil {
		t.Fatal("register exact visitor source", err)
	}
	ids := []string{created.Id}
	permission, err := visitorAPI.CreateEnvironmentVisitorPermissionWithResponse(t.Context(), f.team, machine.JSON201.Id, authorityv1.EnvironmentVisitorPermissionRequest{ProjectKey: f.project, Scope: authorityv1.EnvironmentPermissionScope{EnvironmentIds: &ids}, Services: []string{"diagnostics"}, MaxDurationSeconds: 3600, ExpiresAt: time.Now().Add(time.Hour)}, retainedVisitorBearer(f.session.AccessToken.String()))
	if err != nil || permission.JSON201 == nil {
		t.Fatal("grant exact visitor preparation", err)
	}
	ephemeralPublic, ephemeral, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, nonce := base64.RawURLEncoding.EncodeToString(ephemeralPublic), rand.Text()
	services := map[string]string{"diagnostics": "http"}
	assertion, err := publisherproof.Sign(machine.JSON201.Id, "first", machineproof.EnvironmentVisitor(permission.JSON201.Id, created.Id, "prepare", encodedPublic, nonce, services), server+"/v1/projects/"+f.project+"/environments/"+created.Id+"/visitors/prepare", source, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(assertion))
	preparation := authorityv1.EnvironmentVisitorPrepareRequest{PermissionId: permission.JSON201.Id, Assertion: assertion, PublicKey: encodedPublic, Nonce: nonce, Services: map[string]controlv1.ServiceProtocol{"diagnostics": "http"}, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession(f.project, permission.JSON201.Id, created.Id, "prepare", encodedPublic, nonce, services, digest)))}
	prepared, err := visitorAPI.PrepareEnvironmentVisitorWithResponse(t.Context(), f.project, created.Id, preparation)
	if err != nil || prepared.JSON200 == nil || prepared.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("prepare the exact instantiated visitor resource", err)
	}
	if prepared.JSON200.Environment != created.Ref || prepared.JSON200.MutationRevision != created.MutationRevision || prepared.JSON200.AppliedDefinitionRevision != definition.Revision || len(prepared.JSON200.Services) != 1 || prepared.JSON200.Services["diagnostics"].ServiceId != created.Services[0].ServiceId || prepared.JSON200.Services["diagnostics"].Protocol != "http" {
		t.Fatal("visitor preparation changed the instantiated environment or saved service")
	}
	for _, private := range []string{"localhost", "9080", `"target"`, `"targets"`, `"target_tls"`, `"group_id"`, assertion, base64.RawURLEncoding.EncodeToString(source)} {
		if strings.Contains(string(prepared.Body), private) {
			t.Fatal("visitor preparation disclosed private publisher configuration or source proof")
		}
	}
	recovered, err := visitorAPI.PrepareEnvironmentVisitorWithResponse(t.Context(), f.project, created.Id, preparation)
	if err != nil || recovered.JSON200 == nil || !reflect.DeepEqual(*recovered.JSON200, *prepared.JSON200) {
		t.Fatal("exact visitor preparation retry changed the descriptor or session", err)
	}
	missing, err := f.client.GetEnvironmentWithResponse(t.Context(), f.project, collection.CollectionId, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || missing.StatusCode() != http.StatusBadRequest {
		t.Fatal("wrong-ID-kind selection lost its exact invalid-request status", err)
	}
	missingID, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	missing, err = f.client.GetEnvironmentWithResponse(t.Context(), f.project, missingID, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || missing.StatusCode() != http.StatusNotFound {
		t.Fatal("valid-shaped absent environment lost its exact not-found status", err)
	}
	updated, err := f.client.UpdateCollectionDefaultWithResponse(t.Context(), f.project, collection.CollectionId, controlv1.UpdateCollectionDefaultRequest{TeamId: f.team, ExpectedRevision: collection.MutationRevision, DefinitionRevision: definition.Revision})
	if err != nil || updated.JSON200 == nil {
		t.Fatal(err)
	}
	stale := request
	stale.Name, stale.IdempotencyKey = "tractor-bad", "tractor-bad"
	assertCollectionHTTPCreateConflict(t, f, stale)
	retired, err := f.client.RetireEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: created.MutationRevision})
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("retire environment", err)
	}
	missing, err = f.client.GetEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || missing.StatusCode() != http.StatusNotFound {
		t.Fatal("retired reference recovered", err)
	}
	assertRetainedHTTPRemoved(t, &http.Client{Transport: f.transport}, "https://control.example.test", f.session.AccessToken.String(), http.MethodGet, "/v1/projects/"+f.project+"/publisher-groups/tractor/connection")
}
