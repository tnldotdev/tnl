package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestIntegrationWorkloadApprovalHTTPRecoveryAndAdmission(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	request := authorityv1.WorkloadApprovalRequest{ProjectKey: "equipment", EnvironmentId: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, Workload: "test", IntentHash: strings.Repeat("a", 64), Trust: machineTrustResponse(f.trust), Services: []string{"api"}, MaxDurationSeconds: 600, ExpiresAt: f.now.Add(time.Hour)}
	approved, err := f.client.ApproveWorkloadWithResponse(ctx, f.team, "explicit-1", request, machineBearer(f.human))
	if err != nil || approved.JSON200 == nil {
		t.Fatalf("approval failed: %+v, %v", approved, err)
	}
	first := *approved.JSON200
	if first.Machine.TeamId != f.team || first.Machine.Id == "" || first.Selection.PermissionId == "" || first.Selection.Environment.EnvironmentId != f.environment.ID || first.Selection.Services["api"] != "http" || len(first.Selection.Services) != 1 {
		t.Fatal("approval lost authoritative scope", first)
	}
	read, err := f.client.GetWorkloadApprovalWithResponse(ctx, f.team, "explicit-1", machineBearer(f.human))
	if err != nil || read.JSON200 == nil || read.JSON200.Machine.Id != first.Machine.Id || read.JSON200.Selection.PermissionId != first.Selection.PermissionId {
		t.Fatalf("lost-reply read: %+v, %v", read, err)
	}
	if read.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("approval receipt is cacheable")
	}
	anonymous, err := f.client.GetWorkloadApprovalWithResponse(ctx, f.team, "explicit-1")
	if err != nil || anonymous.StatusCode() != 401 {
		t.Fatal("anonymous receipt read", anonymous, err)
	}
	_, ephemeral, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(environment string) *authorityv1.PrepareEnvironmentVisitorResponse {
		t.Helper()
		result, err := f.client.PrepareEnvironmentVisitorWithResponse(ctx, "equipment", environment, f.prepareBody(t, first.Selection.PermissionId, environment, "prepare", rand.Text(), first.Machine.Id, nil, ephemeral))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := prepare(f.environment.ID); result.JSON200 == nil {
		t.Fatal("approved exact identity was not admitted", result)
	}
	if result := prepare(f.otherEnvironment.ID); result.StatusCode() != 403 {
		t.Fatal("approval leaked to another environment", result)
	}
	if revoked, err := f.client.RevokeEnvironmentVisitorPermissionWithResponse(ctx, f.team, first.Selection.PermissionId, machineBearer(f.human)); err != nil || revoked.StatusCode() != 204 {
		t.Fatal("revoke permission", revoked, err)
	}
	for _, method := range []string{"read", "retry"} {
		var recovered *authorityv1.WorkloadApproval
		if method == "read" {
			r, err := f.client.GetWorkloadApprovalWithResponse(ctx, f.team, "explicit-1", machineBearer(f.human))
			if err != nil {
				t.Fatal(err)
			}
			recovered = r.JSON200
		} else {
			r, err := f.client.ApproveWorkloadWithResponse(ctx, f.team, "explicit-1", request, machineBearer(f.human))
			if err != nil {
				t.Fatal(err)
			}
			recovered = r.JSON200
		}
		if recovered == nil || recovered.Selection.PermissionId != first.Selection.PermissionId || recovered.Machine.Id != first.Machine.Id || recovered.PermissionRevokedAt == nil {
			t.Fatal("revocation replaced authority on recovery", method, recovered)
		}
	}
	if result := prepare(f.environment.ID); result.StatusCode() != 403 {
		t.Fatal("old intent retry restored visitor access", result)
	}
	changed := request
	changed.Services = []string{"secret"}
	conflict, err := f.client.ApproveWorkloadWithResponse(ctx, f.team, "explicit-1", changed, machineBearer(f.human))
	if err != nil || conflict.StatusCode() != 409 {
		t.Fatal("changed intent did not conflict", conflict, err)
	}
	fresh, err := f.client.ApproveWorkloadWithResponse(ctx, f.team, "explicit-2", request, machineBearer(f.human))
	if err != nil || fresh.JSON200 == nil || fresh.JSON200.Selection.PermissionId == first.Selection.PermissionId || fresh.JSON200.Machine.Id != first.Machine.Id {
		t.Fatal("new explicit permission did not reuse exact machine", fresh, err)
	}
}
