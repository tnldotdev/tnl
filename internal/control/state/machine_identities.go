package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

var ErrMachineDenied = errors.New("machine identity or current scoped permission does not authorize this operation")

type MachineIdentity struct {
	ID        string             `json:"id"`
	TeamID    string             `json:"team_id"`
	Name      string             `json:"name"`
	ProofKind string             `json:"proof_kind"`
	Trust     oidc.WorkloadTrust `json:"trust"`
	Revision  int64              `json:"revision"`
}

type RegisterMachineRequest struct {
	TeamID, ActorID, Name, ProofKind, KeyID string
	Trust                                   oidc.WorkloadTrust
	PublicKey                               ed25519.PublicKey
}

func (d *Database) machineManagerTransaction(ctx context.Context, team, actor string) (pgx.Tx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err == nil {
		err = serviceManager(ctx, tx, team, actor)
	}
	if err != nil {
		rollback(ctx, tx, "authorize machine manager", &err)()
		return nil, err
	}
	return tx, nil
}

func (d *Database) RegisterMachineIdentity(ctx context.Context, r RegisterMachineRequest, now time.Time) (result MachineIdentity, retErr error) {
	if !config.ExactWorkloadValue(r.Name) || len(r.Name) > 128 {
		return result, ErrProjectConfigurationInvalid
	}
	switch r.ProofKind {
	case "oidc":
		// generic OIDC deliberately requires an exact subject, not a wildcard or
		// provider metadata copied from an unverified token.
		p := ProjectWorkload{Provider: "oidc", Trust: r.Trust}
		if r.Trust.Provider != "oidc" || r.Trust.Claims["sub"] == "" || p.validateTrust() != nil || len(r.PublicKey) != 0 || r.KeyID != "" {
			return result, ErrProjectConfigurationInvalid
		}
	case "signing_key":
		if len(r.PublicKey) != ed25519.PublicKeySize || !config.ExactWorkloadValue(r.KeyID) || len(r.KeyID) > 128 || r.Trust.Provider != "" || r.Trust.Issuer != "" || r.Trust.JWKSURL != "" || r.Trust.Audience != "" || len(r.Trust.Claims) != 0 {
			return result, ErrProjectConfigurationInvalid
		}
	default:
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.machineManagerTransaction(ctx, r.TeamID, r.ActorID)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "register machine identity", &retErr)()
	id, err := opaqueid.New("mci_")
	if err != nil {
		return result, err
	}
	trust, _ := json.Marshal(r.Trust)
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_identities(id,team_id,name,proof_kind,trust,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, id, r.TeamID, r.Name, r.ProofKind, string(trust), now)
	if err != nil {
		return result, projectConstraintError(err)
	}
	if r.ProofKind == "signing_key" {
		if _, err = tx.Exec(ctx, `INSERT INTO control.machine_identity_keys(machine_id,key_id,public_key) VALUES($1,$2,$3)`, id, r.KeyID, []byte(r.PublicKey)); err != nil {
			return result, err
		}
	} else {
		// registration establishes a durable revocation boundary. sessions issued
		// before registration have no machine link, so revoke matching subjects
		// rather than leaving a legacy credential outside that boundary.
		if _, err = tx.Exec(ctx, `UPDATE control.workload_sessions SET revoked_at=COALESCE(revoked_at,$5) WHERE team_id=$1 AND provider='oidc' AND claims->>'issuer'=$2 AND claims->>'audience'=$3 AND claims->>'subject'=$4`, r.TeamID, r.Trust.Issuer, r.Trust.Audience, r.Trust.Claims["sub"], now); err != nil {
			return result, err
		}
	}
	return MachineIdentity{ID: id, TeamID: r.TeamID, Name: r.Name, ProofKind: r.ProofKind, Trust: r.Trust, Revision: 1}, tx.Commit(ctx)
}

// manager rotation invalidates all old provisioning tokens and linked visitor
// sessions. key IDs and public keys cannot be reused after revocation.
func (d *Database) RotateMachineIdentityKey(ctx context.Context, team, id, actor, key string, public ed25519.PublicKey, now time.Time) (retErr error) {
	if !config.ExactWorkloadValue(key) || len(key) > 128 || len(public) != ed25519.PublicKeySize {
		return ErrProjectConfigurationInvalid
	}
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "rotate machine identity key", &retErr)()
	var kind string
	if err = tx.QueryRow(ctx, `SELECT proof_kind FROM control.machine_identities WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL FOR UPDATE`, id, team).Scan(&kind); err != nil {
		return publisherLookupError(err, ErrMachineDenied)
	}
	if kind != "signing_key" {
		return ErrMachineDenied
	}
	if _, err = tx.Exec(ctx, `UPDATE control.machine_identity_keys SET revoked_at=COALESCE(revoked_at,$2) WHERE machine_id=$1`, id, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.machine_identity_keys(machine_id,key_id,public_key) VALUES($1,$2,$3)`, id, key, []byte(public)); err != nil {
		return projectConstraintError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE control.machine_identities SET revision=revision+1 WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) RevokeMachineIdentity(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke machine identity", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.machine_identities SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND team_id=$2`, id, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}

func machineIdentity(ctx context.Context, tx pgx.Tx, id string) (r MachineIdentity, err error) {
	var trust []byte
	err = tx.QueryRow(ctx, `SELECT m.id,m.team_id,m.name,m.proof_kind,m.trust,m.revision FROM control.machine_identities m JOIN control.teams t ON t.id=m.team_id WHERE m.id=$1 AND m.revoked_at IS NULL AND t.deleted_at IS NULL FOR UPDATE OF m`, id).Scan(&r.ID, &r.TeamID, &r.Name, &r.ProofKind, &trust, &r.Revision)
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	err = json.Unmarshal(trust, &r.Trust)
	return r, err
}

// lookup supplies only manager-saved verification policy. callers must verify
// before exchange, which rereads the current identity under the team lock.
func (d *Database) MachineIdentityPolicy(ctx context.Context, id string) (r MachineIdentity, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "read machine identity policy", &retErr)()
	return machineIdentity(ctx, tx, id)
}

type MachineProof struct {
	Assertion string
	Execution oidc.WorkloadExecution
}

// OIDC executions are passed only from the serving verifier. registered-key
// proofs reuse publisherproof's strict algorithm, audience and lifetime checks.
func verifyMachineProof(ctx context.Context, tx pgx.Tx, m MachineIdentity, p MachineProof, scope, audience string, now time.Time) (time.Time, []byte, error) {
	if m.ProofKind == "oidc" {
		c := p.Execution
		if c.Validate(now) != nil || !c.Matches(m.Trust) || c.AssertionDigest != sha256.Sum256([]byte(p.Assertion)) {
			return time.Time{}, nil, ErrMachineDenied
		}
		d := c.AssertionDigest
		return time.Unix(c.ExpiresAt, 0), d[:], nil
	}
	key, err := publisherproof.KeyID(p.Assertion)
	if err != nil {
		return time.Time{}, nil, ErrMachineDenied
	}
	var public []byte
	if err = tx.QueryRow(ctx, `SELECT public_key FROM control.machine_identity_keys WHERE machine_id=$1 AND key_id=$2 AND revoked_at IS NULL`, m.ID, key).Scan(&public); err != nil {
		return time.Time{}, nil, publisherLookupError(err, ErrMachineDenied)
	}
	a, err := publisherproof.Verify(p.Assertion, m.ID, key, scope, audience, public, now)
	if err != nil {
		return time.Time{}, nil, ErrMachineDenied
	}
	// consume the signed jti, not just the encoded JWT: changing JSON or the
	// expiry while keeping a jti cannot replay the same machine proof.
	d := sha256.Sum256([]byte(key + "\x00" + a.ID))
	return a.Until, d[:], nil
}

func consumeMachineProof(ctx context.Context, tx pgx.Tx, id string, digest []byte, until time.Time) error {
	tag, err := tx.Exec(ctx, `INSERT INTO control.machine_proof_uses(machine_id,proof_digest,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, digest, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return nil
}

func approvedTemplates(c ProjectConfiguration, templates []string) bool {
	if len(templates) == 0 || len(templates) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range templates {
		if !naming.ValidServiceName(name) || !c.PublisherGroups[name].Template || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func validMachineOperations(operations []ProvisioningOperation) bool {
	if len(operations) == 0 || len(operations) > 6 {
		return false
	}
	seen := map[ProvisioningOperation]bool{}
	for _, op := range operations {
		if !op.Valid() || seen[op] {
			return false
		}
		seen[op] = true
	}
	return true
}

func sortedTemplates(templates []string) []string {
	v := slices.Clone(templates)
	slices.Sort(v)
	return v
}
