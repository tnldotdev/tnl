package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (f machineAPIFixture) prepareState(t *testing.T, body authorityv1.EnvironmentVisitorPrepareRequest) controlstate.PrepareEnvironmentVisitorRequest {
	t.Helper()
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil {
		t.Fatal(err)
	}
	services := make(map[string]string, len(body.Services))
	for name, protocol := range body.Services {
		services[name] = string(protocol)
	}
	return controlstate.PrepareEnvironmentVisitorRequest{ProjectKey: "equipment", EnvironmentID: f.environment.ID, PermissionID: body.PermissionId,
		Audience: f.server.URL + "/v1/projects/equipment/environments/" + f.environment.ID + "/visitors/prepare", Nonce: body.Nonce,
		PublicKey: public, Signature: signature, Services: services, Proof: controlstate.MachineProof{Assertion: body.Assertion}}
}

func (f machineAPIFixture) inspectDatabase(t *testing.T) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := connection.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return connection
}

func TestIntegrationMachineEnvironmentVisitorFixedDeadlinesAndRenewalReplay(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, sourceKey := f.register(t, "signing_key")
	permission, err := f.client.CreateEnvironmentVisitorPermissionWithResponse(t.Context(), f.team, machine, authorityv1.EnvironmentVisitorPermissionRequest{ProjectKey: "equipment", Scope: machineEnvironmentScope(f.environment.ID), Services: []string{"api"}, MaxDurationSeconds: 45, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || permission.JSON201 == nil {
		t.Fatal("create permission", err)
	}
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	body := f.prepareBody(t, permission.JSON201.Id, f.environment.ID, "prepare", rand.Text(), machine, sourceKey, ephemeral)
	initial, err := f.d.PrepareEnvironmentVisitor(t.Context(), f.prepareState(t, body), f.now)
	if err != nil {
		t.Fatal("prepare", err)
	}
	session := initial.Session
	deadline := f.now.Add(45 * time.Second)
	if session.ExpiresAt == nil || !session.ExpiresAt.Equal(deadline) || !session.LeaseExpiresAt.Equal(deadline) {
		t.Fatal("initial admission lost its fixed deadline")
	}
	audience := f.server.URL + "/v1/environment-visitor-sessions/" + session.ID + "/assertions"
	raw, err := publisherproof.Sign(machine, "first", machineproof.EnvironmentVisitor(permission.JSON201.Id, f.environment.ID, "attach", body.PublicKey, session.ID, map[string]string{"api": "http"}), audience, sourceKey, f.now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(raw))
	signature := ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permission.JSON201.Id, f.environment.ID, "attach", body.PublicKey, session.ID, map[string]string{"api": "http"}, digest))
	attached, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, controlstate.MachineProof{Assertion: raw}, signature, audience, f.now.Add(30*time.Second))
	if err != nil || !attached.ExpiresAt.Equal(deadline) || attached.LeaseExpiresAt.After(deadline) || !reflect.DeepEqual(attached.ServiceIDs, session.ServiceIDs) {
		t.Fatal("fresh source proof extended the original session or service scope", err)
	}
	renewal := controlstate.WorkloadRenewal{Sequence: 1, Signature: ed25519.Sign(ephemeral, workloadproof.Renew(session.ID, 1))}
	renewed, err := f.d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, renewal, f.now.Add(31*time.Second))
	if err != nil || renewed.RenewalSequence != 1 || !renewed.LeaseExpiresAt.Equal(deadline) {
		t.Fatal("renewal lost fixed deadline or sequence", err)
	}
	replay, err := f.d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, renewal, f.now.Add(32*time.Second))
	if err != nil || !replay.LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) || !replay.RenewAfter.Equal(renewed.RenewAfter) {
		t.Fatal("renewal retry spent its sequence twice", err)
	}
	if _, err := f.d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, renewal, f.now.Add(46*time.Second)); !errors.Is(err, controlstate.ErrWorkloadExpired) {
		t.Fatal("renewal revived expired fixed deadline", err)
	}
	if err := f.d.RevokeEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, f.now.Add(2*time.Hour)); err != nil {
		t.Fatal("original session credential could not clean up after source expiry", err)
	}
	if _, err := f.d.PrepareEnvironmentVisitor(t.Context(), f.prepareState(t, body), f.now); err == nil {
		t.Fatal("prepare replay restored a revoked session")
	}
}

func TestIntegrationMachineEnvironmentVisitorRechecksRevocationAfterTeamWait(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, key := f.register(t, "signing_key")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	request := f.prepareState(t, f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, key, ephemeral))
	connection := f.inspectDatabase(t)
	tx, err := connection.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('tnl:local-team:'||$1::text,0))`, f.team); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.d.PrepareEnvironmentVisitor(ctx, request, f.now)
		done <- err
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	for {
		var waiting bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%LockLocalTeamForMutation%')`).Scan(&waiting); err != nil {
			t.Fatal("observe team guard wait", err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("admission bypassed held team guard", err)
		default:
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE control.machine_workload_permissions SET revoked_at=$2 WHERE id=$1`, permission, f.now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	if !errors.Is(err, controlstate.ErrMachineDenied) {
		t.Fatal("wait reused authority from before revocation", err)
	}
	var sessions int
	if err := connection.QueryRow(t.Context(), `SELECT count(*) FROM control.workload_sessions WHERE session_nonce=$1`, request.Nonce).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("denied wait committed a visitor principal", sessions, err)
	}
}

func TestIntegrationMachineEnvironmentVisitorRevocationInvalidatesPolicyAndCleanup(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, key := f.register(t, "signing_key")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	initial, err := f.d.PrepareEnvironmentVisitor(t.Context(), f.prepareState(t, f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, key, ephemeral)), f.now)
	if err != nil {
		t.Fatal(err)
	}
	session, connection := initial.Session, f.inspectDatabase(t)
	var before, after int64
	query := `SELECT revision FROM control.visitor_policies WHERE resource_kind='service' AND resource_id=$1`
	if err := connection.QueryRow(t.Context(), query, session.ServiceIDs[0]).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := f.d.RevokeEnvironmentVisitorPermission(t.Context(), f.team, permission, f.actor, f.now); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(t.Context(), query, session.ServiceIDs[0]).Scan(&after); err != nil || after <= before {
		t.Fatal("revocation did not invalidate issued service policy", before, after, err)
	}
	if _, err := f.d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], f.now); err == nil {
		t.Fatal("revoked visitor still passed service admission")
	}
	if err := f.d.RevokeEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, f.now.Add(24*time.Hour)); err != nil {
		t.Fatal("permission revocation blocked original-session cleanup", err)
	}
	if err := f.d.RevokeEnvironmentVisitorSession(t.Context(), session.ID, "wlc_"+strings.Repeat("x", 43), f.now); err == nil {
		t.Fatal("another credential revoked the session")
	}
}

func TestIntegrationMachineEnvironmentVisitorCannotReuseSourceJTIForAnotherIntent(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, sourceKey := f.register(t, "signing_key")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	first := f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, sourceKey, ephemeral)
	initial, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, first)
	if err != nil || initial.JSON200 == nil {
		t.Fatal("initial intent", err)
	}
	second := f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, sourceKey, ephemeral)
	claims := func(raw string) map[string]any {
		t.Helper()
		data, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	changed := claims(second.Assertion)
	changed["jti"] = claims(first.Assertion)["jti"]
	encoded, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	message := strings.Split(second.Assertion, ".")[0] + "." + base64.RawURLEncoding.EncodeToString(encoded)
	second.Assertion = message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sourceKey, []byte(message)))
	digest := sha256.Sum256([]byte(second.Assertion))
	second.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permission, f.environment.ID, "prepare", second.PublicKey, second.Nonce, map[string]string{"api": "http"}, digest)))
	denied, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, second)
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("validly signed second intent reused the consumed source jti", err)
	}
	connection := f.inspectDatabase(t)
	var sessions int
	if err := connection.QueryRow(t.Context(), `SELECT count(*) FROM control.workload_session_machines WHERE permission_id=$1`, permission).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("replayed source proof created another visitor session", sessions, err)
	}
}

func TestIntegrationMachineEnvironmentVisitorApplyCannotReplaceIssuedServiceIdentity(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, key := f.register(t, "signing_key")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	body := f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, key, ephemeral)
	initial, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
	if err != nil || initial.JSON200 == nil {
		t.Fatal(err)
	}
	oldID := initial.JSON200.Services["api"].ServiceId
	definition, err := f.d.CreateServiceDefinition(t.Context(), controlstate.CreateServiceDefinitionRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor, SourceFingerprint: strings.Repeat("a", 64),
		Definition: controlstate.ServiceDefinition{Services: map[string]controlstate.ServiceDefinitionService{"secret": {Protocol: "tcp"}}}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := f.d.ApplyEnvironment(t.Context(), controlstate.ApplyEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor,
		EnvironmentApplication: controlstate.EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := f.d.ApplyEnvironment(t.Context(), controlstate.ApplyEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor,
		EnvironmentApplication: controlstate.EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: removed.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision, Targets: f.environment.Targets}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	var restoredID string
	for _, service := range rolledBack.Services {
		if service.Service == "api" {
			restoredID = service.ServiceID
		}
	}
	if restoredID == "" || restoredID == oldID {
		t.Fatal("retired service identity was reused by definition rollback")
	}
	replay, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
	if err != nil || replay.StatusCode() != 409 {
		t.Fatal("same nonce silently substituted a replacement service", err)
	}
	session := initial.JSON200.Session
	for _, service := range []string{oldID, restoredID} {
		if _, err := f.d.CheckWorkloadService(t.Context(), session.Credential, service, f.now); err == nil {
			t.Fatal("old session reached a retired or replacement service")
		}
	}
}
