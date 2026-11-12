package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationMachineRegistrationIsolatesLinkedVisitorSessions(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	public, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: f.server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, controlpublic.DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Config.Handler.(*http.ServeMux).Handle("/", public)
	visitor, err := controlv1.NewClientWithResponses(f.server.URL, controlv1.WithHTTPClient(f.server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(token string) controlv1.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+token)
			return nil
		}
	}
	checkAccess := func(session authorityv1.EnvironmentVisitorSession, service string, want int) {
		t.Helper()
		inventory, err := visitor.ListWorkloadServicesWithResponse(ctx, bearer(session.Credential))
		if err != nil {
			t.Fatal(err)
		}
		if inventory.StatusCode() != want {
			t.Fatalf("visitor inventory status = %d, want %d", inventory.StatusCode(), want)
		}
		if want == http.StatusOK && (inventory.JSON200 == nil || len(inventory.JSON200.Services) != 1 || inventory.JSON200.Services[0].Id != service) {
			t.Fatal("visitor inventory lost its exact issued service")
		}
		decision, err := visitor.CheckWorkloadServiceWithResponse(ctx, service, bearer(session.Credential))
		if err != nil {
			t.Fatal(err)
		}
		if decision.StatusCode() != want {
			t.Fatalf("visitor service authorization status = %d, want %d", decision.StatusCode(), want)
		}
		if want == http.StatusOK && (decision.JSON200 == nil || decision.JSON200.ServiceId != service || decision.JSON200.Subject.WorkloadSessionId == nil || *decision.JSON200.Subject.WorkloadSessionId != session.Id) {
			t.Fatal("service authorization lost the admitted visitor subject")
		}
	}
	claims := f.claims()
	claims["tenant"] = "second-environment"
	assertion := f.issuer.Sign(t, claims)
	request := func(permission, environment, nonce string, key ed25519.PrivateKey) authorityv1.EnvironmentVisitorPrepareRequest {
		public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		digest := sha256.Sum256([]byte(assertion))
		return authorityv1.EnvironmentVisitorPrepareRequest{PermissionId: permission, Nonce: nonce, PublicKey: public, Assertion: assertion,
			Services: map[string]controlv1.ServiceProtocol{"api": "http"}, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,
				machineproof.EnvironmentVisitorPossession("equipment", permission, environment, "prepare", public, nonce, map[string]string{"api": "http"}, digest)))}
	}
	prepare := func(environment string, body authorityv1.EnvironmentVisitorPrepareRequest) authorityv1.EnvironmentVisitorPreparation {
		t.Helper()
		r, err := f.client.PrepareEnvironmentVisitorWithResponse(ctx, "equipment", environment, body)
		if err != nil {
			t.Fatal(err)
		}
		if r.JSON200 == nil {
			t.Fatalf("visitor preparation status = %d, want 200", r.StatusCode())
		}
		return *r.JSON200
	}
	machineA, _ := f.register(t, "oidc")
	permissionA := f.permission(t, machineA, machineEnvironmentScope(f.environment.ID))
	_, keyA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bodyA := request(permissionA, f.environment.ID, rand.Text(), keyA)
	admittedA := prepare(f.environment.ID, bodyA)
	serviceA := admittedA.Services["api"].ServiceId
	checkAccess(admittedA.Session, serviceA, http.StatusOK)
	inspect := f.inspectDatabase(t)
	var linkedMachine, linkedPermission, linkedEnvironment string
	if err := inspect.QueryRow(ctx, `SELECT machine_id,permission_id,environment_id FROM control.workload_session_machines WHERE session_id=$1`, admittedA.Session.Id).Scan(&linkedMachine, &linkedPermission, &linkedEnvironment); err != nil || linkedMachine != machineA || linkedPermission != permissionA || linkedEnvironment != f.environment.ID {
		t.Fatal("first visitor was not linked to its exact saved authority", err)
	}
	saved := func(id string) []byte {
		t.Helper()
		var row []byte
		if err := inspect.QueryRow(ctx, `SELECT to_jsonb(session)::text FROM control.workload_sessions session WHERE id=$1`, id).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	beforeA := saved(admittedA.Session.Id)
	trustB := f.trust
	trustB.Claims = maps.Clone(f.trust.Claims)
	trustB.Claims["tenant"] = claims["tenant"].(string)
	approved, err := f.client.ApproveWorkloadWithResponse(ctx, f.team, "independent-environment", authorityv1.WorkloadApprovalRequest{
		ProjectKey: "equipment", EnvironmentId: f.otherEnvironment.ID, ExpectedRevision: f.otherEnvironment.MutationRevision,
		Workload: "second", IntentHash: strings.Repeat("b", 64), Trust: machineTrustResponse(trustB), Services: []string{"api"},
		MaxDurationSeconds: 600, ExpiresAt: f.now.Add(time.Hour),
	}, machineBearer(f.human))
	if err != nil {
		t.Fatal(err)
	}
	if approved.JSON200 == nil {
		t.Fatalf("independent workload approval status = %d, want 200", approved.StatusCode())
	}
	approvalB := approved.JSON200
	if approvalB.Machine.Id == machineA || approvalB.Machine.Trust == nil || approvalB.Machine.Trust.Claims["tenant"] != trustB.Claims["tenant"] || approvalB.Selection.Environment.EnvironmentId != f.otherEnvironment.ID || approvalB.Selection.PermissionId == permissionA {
		t.Fatal("different exact trust reused the first machine or visitor scope")
	}
	if !bytes.Equal(beforeA, saved(admittedA.Session.Id)) {
		t.Fatal("registering an independently approved machine changed an existing linked visitor session")
	}
	checkAccess(admittedA.Session, serviceA, http.StatusOK)
	_, keyB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	admittedB := prepare(f.otherEnvironment.ID, request(approvalB.Selection.PermissionId, f.otherEnvironment.ID, rand.Text(), keyB))
	serviceB := admittedB.Services["api"].ServiceId
	if admittedB.Session.Id == admittedA.Session.Id || serviceB == serviceA {
		t.Fatal("independent environments shared visitor session or saved service identity")
	}
	checkAccess(admittedB.Session, serviceB, http.StatusOK)
	beforeB := saved(admittedB.Session.Id)
	if retry := prepare(f.environment.ID, bodyA); retry.Session.Id != admittedA.Session.Id || retry.Session.Credential != admittedA.Session.Credential || !bytes.Equal(beforeA, saved(admittedA.Session.Id)) {
		t.Fatal("independent approval changed original-nonce recovery")
	}
	takeover, err := f.client.PrepareEnvironmentVisitorWithResponse(ctx, "equipment", f.environment.ID, request(permissionA, f.environment.ID, bodyA.Nonce, keyB))
	if err != nil || takeover.StatusCode() != http.StatusConflict || !bytes.Equal(beforeA, saved(admittedA.Session.Id)) {
		t.Fatal("another key took over the original nonce or changed accepted authority", err)
	}
	independentA := prepare(f.environment.ID, request(permissionA, f.environment.ID, rand.Text(), keyB))
	if independentA.Session.Id == admittedA.Session.Id {
		t.Fatal("fresh nonce did not receive separately key-bound authority")
	}
	checkAccess(independentA.Session, serviceA, http.StatusOK)
	revoked, err := f.client.RevokeMachineIdentityWithResponse(ctx, f.team, machineA, machineBearer(f.human))
	if err != nil || revoked.StatusCode() != http.StatusNoContent {
		t.Fatal("explicit first-machine revocation failed", err)
	}
	checkAccess(admittedA.Session, serviceA, http.StatusForbidden)
	checkAccess(independentA.Session, serviceA, http.StatusForbidden)
	if !bytes.Equal(beforeB, saved(admittedB.Session.Id)) {
		t.Fatal("revoking the first machine changed the independent visitor session")
	}
	checkAccess(admittedB.Session, serviceB, http.StatusOK)
}
