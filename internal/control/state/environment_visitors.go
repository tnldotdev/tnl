package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

type PrepareEnvironmentVisitorRequest struct {
	ProjectKey, EnvironmentID, PermissionID, Audience, Nonce string
	PublicKey                                                ed25519.PublicKey
	Signature                                                []byte
	Services                                                 map[string]string
	Proof                                                    MachineProof
}

type EnvironmentVisitorPreparation struct {
	ProjectKey, EnvironmentID                   string
	AppliedDefinitionRevision, MutationRevision int64
	Session                                     WorkloadSession
	Services                                    map[string]WorkloadService
}

type environmentVisitorPermission struct {
	machine     MachineIdentity
	services    []string
	deadline    time.Time
	maxDuration int
}

func lockEnvironmentVisitorPermission(ctx context.Context, tx pgx.Tx, team, project, environment, permission string) (p environmentVisitorPermission, err error) {
	var machine, collection string
	var future bool
	var captured []string
	err = tx.QueryRow(ctx, `SELECT machine_id,COALESCE(collection_id,''),include_future_environments,environment_ids,services,expires_at,max_duration_seconds FROM control.machine_workload_permissions WHERE id=$1 AND team_id=$2 AND project_key=$3 AND revoked_at IS NULL FOR UPDATE`, permission, team, project).Scan(&machine, &collection, &future, &captured, &p.services, &p.deadline, &p.maxDuration)
	if err != nil {
		return p, publisherLookupError(err, ErrMachineDenied)
	}
	if err = checkEnvironmentPermissionScope(ctx, tx, team, project, environment, "", collection, future, captured); err != nil {
		return p, err
	}
	p.machine, err = machineIdentity(ctx, tx, machine)
	if err != nil {
		return p, err
	}
	if p.machine.TeamID != team {
		return p, ErrMachineDenied
	}
	return p, nil
}

func environmentVisitorExecution(machine MachineIdentity, permission, audience string, proof MachineProof, until time.Time) oidc.WorkloadExecution {
	if machine.ProofKind == "oidc" {
		return proof.Execution
	}
	key, _ := publisherproof.KeyID(proof.Assertion)
	origin := strings.Split(audience, "/v1/")[0]
	issued := until.Add(-publisherproof.AssertionLifetime).Unix()
	return oidc.WorkloadExecution{Provider: "oidc", Issuer: origin, Subject: machine.ID, Audience: origin, TrustDigest: machine.Trust.Digest(), IssuedAt: issued, NotBefore: issued, ExpiresAt: until.Unix(), AssertionDigest: sha256.Sum256([]byte(proof.Assertion)), RegisteredMachine: &oidc.RegisteredMachineExecution{ID: machine.ID, KeyID: key, PermissionID: permission, Revision: machine.Revision}}
}

func (d *Database) PrepareEnvironmentVisitor(ctx context.Context, r PrepareEnvironmentVisitorRequest, now time.Time) (result EnvironmentVisitorPreparation, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !opaqueid.Valid(r.EnvironmentID, opaqueid.EnvironmentPrefix) || !opaqueid.Valid(r.PermissionID, "mwp_") || !workloadproof.ValidNonce(r.Nonce) || len(r.PublicKey) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize || len(r.Services) < 1 || len(r.Services) > 32 {
		return result, ErrEnvironmentInvalid
	}
	for name, protocol := range r.Services {
		if !naming.ValidServiceName(name) || (ServiceMetadata{Protocol: protocol}).Validate() != nil {
			return result, ErrEnvironmentInvalid
		}
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "prepare environment visitor", &retErr)()
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.machine_workload_permissions WHERE id=$1 AND project_key=$2`, r.PermissionID, r.ProjectKey).Scan(&team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: r.ProjectKey}); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	permission, err := lockEnvironmentVisitorPermission(ctx, tx, team, r.ProjectKey, r.EnvironmentID, r.PermissionID)
	if err != nil {
		return result, err
	}
	environment, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: team, ProjectKey: r.ProjectKey, ID: r.EnvironmentID})
	if err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	public := base64.RawURLEncoding.EncodeToString(r.PublicKey)
	until, proofDigest, err := verifyMachineProof(ctx, tx, permission.machine, r.Proof, machineproof.EnvironmentVisitor(r.PermissionID, r.EnvironmentID, "prepare", public, r.Nonce, r.Services), r.Audience, clock.current())
	if err != nil {
		return EnvironmentVisitorPreparation{}, err
	}
	assertionDigest := sha256.Sum256([]byte(r.Proof.Assertion))
	if !ed25519.Verify(r.PublicKey, machineproof.EnvironmentVisitorPossession(r.ProjectKey, r.PermissionID, r.EnvironmentID, "prepare", public, r.Nonce, r.Services, assertionDigest), r.Signature) {
		return EnvironmentVisitorPreparation{}, ErrMachineDenied
	}
	execution := environmentVisitorExecution(permission.machine, r.PermissionID, r.Audience, r.Proof, until)
	if execution.Validate(clock.current()) != nil || !permission.deadline.After(clock.current()) {
		return EnvironmentVisitorPreparation{}, ErrMachineDenied
	}
	// deny services outside the saved allowlist before comparing replay intent.
	// an existing nonce does not turn missing authority into a selection conflict.
	if !environmentPermissionServicesContain(permission.services, sortedProjectKeys(r.Services)) {
		return EnvironmentVisitorPreparation{}, ErrMachineDenied
	}
	intent, _ := json.Marshal([]any{r.PermissionID, r.EnvironmentID, r.Services, execution.IdentityDigest()})
	requestDigest := sha256.Sum256(intent)
	var id string
	var previous, previousPublic []byte
	err = tx.QueryRow(ctx, `SELECT id,public_key,request_digest FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2 AND session_nonce=$3 FOR UPDATE`, team, r.ProjectKey, r.Nonce).Scan(&id, &previousPublic, &previous)
	replay := err == nil
	original := map[string]string{}
	if replay {
		if !bytes.Equal(previousPublic, r.PublicKey) || !bytes.Equal(previous, requestDigest[:]) {
			return EnvironmentVisitorPreparation{}, ErrWorkloadConflict
		}
		// retain the immutable admission, including removed services. a retry can
		// recover fewer original IDs, but a reused name cannot substitute a new ID.
		rows, e := tx.Query(ctx, `SELECT service,service_id FROM control.workload_session_services WHERE workload_session_id=$1 ORDER BY service`, id)
		if e != nil {
			return EnvironmentVisitorPreparation{}, e
		}
		for rows.Next() {
			var name, service string
			if e = rows.Scan(&name, &service); e != nil {
				rows.Close()
				return EnvironmentVisitorPreparation{}, e
			}
			original[name] = service
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return EnvironmentVisitorPreparation{}, e
		}
		if len(original) != len(r.Services) {
			return EnvironmentVisitorPreparation{}, ErrWorkloadConflict
		}
		for name := range r.Services {
			if original[name] == "" {
				return EnvironmentVisitorPreparation{}, ErrWorkloadConflict
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return EnvironmentVisitorPreparation{}, err
	}
	_, _, projection, err := d.environmentProjection(ctx, tx, environment)
	if err != nil {
		return result, err
	}
	result = EnvironmentVisitorPreparation{ProjectKey: r.ProjectKey, EnvironmentID: r.EnvironmentID, AppliedDefinitionRevision: environment.AppliedDefinitionRevision, MutationRevision: environment.MutationRevision, Services: map[string]WorkloadService{}}
	for _, name := range sortedProjectKeys(r.Services) {
		configuration, found := projection[name]
		if !found {
			if replay {
				continue
			}
			return EnvironmentVisitorPreparation{}, ErrMachineDenied
		}
		// service identity comes from the saved environment binding, never a
		// caller-provided endpoint or a name lookup in another scope.
		var id string
		if err = tx.QueryRow(ctx, `SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND group_id=$3 AND service=$4 AND public_url_id IS NULL FOR UPDATE`, team, r.ProjectKey, environment.GroupID, publisherGroupServiceKey(environment.GroupID, name)).Scan(&id); err != nil {
			return EnvironmentVisitorPreparation{}, publisherLookupError(err, ErrMachineDenied)
		}
		if replay && original[name] != id {
			return EnvironmentVisitorPreparation{}, ErrWorkloadConflict
		}
		service, e := q.LockService(ctx, id)
		if e != nil {
			return EnvironmentVisitorPreparation{}, e
		}
		if service.TeamID != team {
			return EnvironmentVisitorPreparation{}, ErrMachineDenied
		}
		if !service.Enabled || service.DeletedAt.Valid || configuration.Protocol != r.Services[name] || service.Protocol != r.Services[name] {
			if replay {
				continue
			}
			return EnvironmentVisitorPreparation{}, ErrMachineDenied
		}
		metadata, e := checkedServiceMetadata(service)
		if e != nil || metadata.Endpoint == nil {
			return EnvironmentVisitorPreparation{}, ErrMachineDenied
		}
		selected := WorkloadService{ID: id, Service: name, Protocol: service.Protocol, Endpoint: metadata.Endpoint}
		if service.Protocol == "kubernetes" {
			selected.KubernetesAuth, err = visitorKubernetesAuthForConfiguration(configuration)
			if err != nil {
				return EnvironmentVisitorPreparation{}, err
			}
		}
		result.Services[name] = selected
	}
	if len(result.Services) == 0 {
		return EnvironmentVisitorPreparation{}, ErrMachineDenied
	}
	if !replay {
		id, err = opaqueid.New("wls_")
		if err != nil {
			return EnvironmentVisitorPreparation{}, err
		}
		secret, _, e := privateSecret()
		if e != nil {
			return EnvironmentVisitorPreparation{}, e
		}
		credential := "wlc_" + secret
		digest := sha256.Sum256([]byte(credential))
		sealed, e := d.storageKey.Seal(workloadCredentialContext(id), []byte(credential))
		if e != nil {
			return EnvironmentVisitorPreparation{}, e
		}
		claims, _ := json.Marshal(execution)
		var repositoryID, runID, runAttempt, checkRunID *string
		if g := execution.GitHub; g != nil {
			repositoryID, runID, runAttempt, checkRunID = &g.RepositoryID, &g.RunID, &g.RunAttempt, &g.CheckRunID
		}
		identityExpiry := minTime(until, permission.deadline)
		var deadline *time.Time
		lease := minTime(now.Add(WorkloadLease), identityExpiry)
		if permission.maxDuration > 0 {
			deadline = new(now.Add(time.Duration(permission.maxDuration) * time.Second))
			lease = minTime(lease, *deadline)
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_sessions(id,team_id,project_key,workload_name,provider,session_nonce,public_key,request_digest,claims,binding,credential_digest,credential_ciphertext,storage_key_id,created_at,renewed_at,lease_expires_at,expires_at,identity_expires_at,repository_id,run_id,run_attempt,check_run_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$14,$15,$16,$17,$18,$19,$20,$21)`, id, team, r.ProjectKey, r.PermissionID, execution.Provider, r.Nonce, []byte(r.PublicKey), requestDigest[:], string(claims), hex.EncodeToString(requestDigest[:]), digest[:], sealed, d.storageKey.CurrentID(), now, lease, deadline, identityExpiry, repositoryID, runID, runAttempt, checkRunID)
		if err != nil {
			return EnvironmentVisitorPreparation{}, err
		}
		protocols, _ := json.Marshal(r.Services)
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_session_machines(session_id,machine_id,identity_revision,permission_id,environment_id,permission_deadline,expected_protocols) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`, id, permission.machine.ID, permission.machine.Revision, r.PermissionID, r.EnvironmentID, permission.deadline, string(protocols))
		if err != nil {
			return EnvironmentVisitorPreparation{}, err
		}
		if permission.machine.ProofKind == "signing_key" {
			if err = consumeMachineProof(ctx, tx, permission.machine.ID, proofDigest, until); err != nil {
				return EnvironmentVisitorPreparation{}, err
			}
		}
		for name, selected := range result.Services {
			if _, err = tx.Exec(ctx, `INSERT INTO control.workload_session_services(workload_session_id,service_id,service) VALUES($1,$2,$3)`, id, selected.ID, name); err != nil {
				return EnvironmentVisitorPreparation{}, err
			}
		}
		if err = workloadAudit(ctx, tx, id, "start", "", now); err != nil {
			return EnvironmentVisitorPreparation{}, err
		}
	}
	result.Session, err = d.workloadSession(ctx, tx, id, clock.current())
	if err != nil {
		return EnvironmentVisitorPreparation{}, err
	}
	if !until.After(clock.current()) || !result.Session.IdentityExpiresAt.After(clock.current()) || !result.Session.LeaseExpiresAt.After(clock.current()) {
		return EnvironmentVisitorPreparation{}, ErrWorkloadExpired
	}
	return result, tx.Commit(ctx)
}

func (d *Database) EnvironmentVisitorAssertionPolicy(ctx context.Context, id, credential string, now time.Time) (result MachineIdentity, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read environment visitor identity policy", &retErr)()
	owner, err := lockWorkloadCredential(ctx, tx, credential, newAuthorizationClock(now))
	if err != nil || owner.ID != id {
		if err == nil {
			err = ErrMachineDenied
		}
		return result, err
	}
	var machine string
	if err = tx.QueryRow(ctx, `SELECT machine_id FROM control.workload_session_machines WHERE session_id=$1`, id).Scan(&machine); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	return machineIdentity(ctx, tx, machine)
}

func (d *Database) AttachEnvironmentVisitorAssertion(ctx context.Context, id, credential string, proof MachineProof, signature []byte, audience string, now time.Time) (result WorkloadSession, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "attach environment visitor assertion", &retErr)()
	owner, err := lockWorkloadCredential(ctx, tx, credential, clock)
	if err != nil {
		return result, err
	}
	if owner.ID != id || len(signature) != ed25519.SignatureSize {
		return result, ErrMachineDenied
	}
	row, err := controlstatedb.New(tx).GetWorkloadSession(ctx, id)
	if err != nil {
		return result, err
	}
	var environment, permissionID string
	var originalPermissionDeadline time.Time
	var encoded []byte
	if err = tx.QueryRow(ctx, `SELECT environment_id,permission_id,permission_deadline,expected_protocols FROM control.workload_session_machines WHERE session_id=$1`, id).Scan(&environment, &permissionID, &originalPermissionDeadline, &encoded); err != nil {
		return result, err
	}
	var services map[string]string
	if json.Unmarshal(encoded, &services) != nil {
		return result, ErrMachineDenied
	}
	permission, err := lockEnvironmentVisitorPermission(ctx, tx, row.TeamID, row.ProjectKey, environment, permissionID)
	if err != nil {
		return result, err
	}
	public := base64.RawURLEncoding.EncodeToString(owner.PublicKey)
	until, proofDigest, err := verifyMachineProof(ctx, tx, permission.machine, proof, machineproof.EnvironmentVisitor(permissionID, environment, "attach", public, id, services), audience, clock.current())
	if err != nil {
		return result, err
	}
	assertionDigest := sha256.Sum256([]byte(proof.Assertion))
	if !ed25519.Verify(owner.PublicKey, machineproof.EnvironmentVisitorPossession(row.ProjectKey, permissionID, environment, "attach", public, id, services, assertionDigest), signature) {
		return result, ErrMachineDenied
	}
	execution := environmentVisitorExecution(permission.machine, permissionID, audience, proof, until)
	var previous oidc.WorkloadExecution
	if json.Unmarshal(row.Claims, &previous) != nil || previous.IdentityDigest() != execution.IdentityDigest() || execution.Validate(clock.current()) != nil {
		return result, ErrMachineDenied
	}
	until = minTime(until, minTime(originalPermissionDeadline, permission.deadline))
	if !until.After(clock.current()) {
		return result, ErrMachineDenied
	}
	if permission.machine.ProofKind == "signing_key" {
		if err = consumeMachineProof(ctx, tx, permission.machine.ID, proofDigest, until); err != nil {
			return result, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET identity_expires_at=GREATEST(identity_expires_at,$2),lease_expires_at=GREATEST(lease_expires_at,LEAST(renewed_at+interval '90 seconds',expires_at,GREATEST(identity_expires_at,$2))) WHERE id=$1`, id, until)
	if err != nil {
		return result, err
	}
	result, err = d.workloadSession(ctx, tx, id, clock.current())
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
