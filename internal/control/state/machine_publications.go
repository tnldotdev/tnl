package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type MachinePublicationPermission struct {
	ID, MachineID, TeamID, Resource, Namespace, DomainID string
	AllowAnonymous                                       bool
	ExpiresAt                                            time.Time
}

func (d *Database) CreateMachinePublicationPermission(ctx context.Context, r MachinePublicationPermission, actor string, now time.Time) (result MachinePublicationPermission, retErr error) {
	if (r.Resource == "") == (r.Namespace == "") || !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(366*24*time.Hour)) {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.machineManagerTransaction(ctx, r.TeamID, actor)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "approve machine publication", &retErr)()
	m, err := machineIdentity(ctx, tx, r.MachineID)
	if err != nil {
		return result, err
	}
	if m.TeamID != r.TeamID {
		return result, ErrMachineDenied
	}
	q := controlstatedb.New(tx)
	var scope PublisherScope
	if r.Resource != "" {
		if r.Namespace != "" || r.DomainID != "" || r.AllowAnonymous {
			return result, ErrProjectConfigurationInvalid
		}
		u, err := q.LockPublicURLForRun(ctx, r.Resource)
		if err != nil {
			return result, publisherLookupError(err, ErrMachineDenied)
		}
		if u.TeamID != r.TeamID || u.Purpose != "app" || u.ServiceProtocol != "http" || u.Ephemeral || u.LifecycleState != "enabled" {
			return result, ErrMachineDenied
		}
		if err = machinePublicationResource(ctx, tx, u.ID, u.CanonicalHostname, now); err != nil {
			return result, err
		}
		scope = PublisherScope{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: r.Resource}
	} else {
		canonical, e := naming.CanonicalizeHostname(r.Namespace)
		if e != nil || canonical != r.Namespace {
			return result, ErrProjectConfigurationInvalid
		}
		domain, e := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: r.DomainID, TeamID: text(r.TeamID)})
		if e != nil {
			return result, publisherLookupError(e, ErrMachineDenied)
		}
		if domain.Kind == "managed" {
			member, e := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: r.TeamID, IdentityID: actor})
			if e != nil {
				return result, e
			}
			approved, e := d.authorizePublisherScope(ctx, q, PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID}, actor, member.ID, uint64(member.PolicyRevision))
			if e != nil {
				return result, e
			}
			scope = approved.publisherScope()
			if r.Namespace != scope.Namespace && !strings.HasSuffix(r.Namespace, "."+scope.Namespace) {
				return result, ErrMachineDenied
			}
			scope.Namespace = r.Namespace
		} else {
			if r.Namespace != domain.CanonicalDomain && !strings.HasSuffix(r.Namespace, "."+domain.CanonicalDomain) {
				return result, ErrMachineDenied
			}
			scope = PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID, Namespace: r.Namespace, PublicURLScope: PublicURLScopeShared}
		}
		if err = machinePublicationNamespace(ctx, tx, r.Namespace, now); err != nil {
			return result, err
		}
	}
	r.ID, err = opaqueid.New("mpp_")
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_publication_permissions(id,machine_id,team_id,public_url_id,domain_id,namespace,membership_id,public_url_scope,allow_anonymous,created_by_identity_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.ID, r.MachineID, r.TeamID, nullableText(scope.PublicURLID), nullableText(scope.DomainID), nullableText(scope.Namespace), nullableText(scope.MembershipID), nullableText(string(scope.PublicURLScope)), r.AllowAnonymous, actor, r.ExpiresAt)
	if err != nil {
		return result, projectConstraintError(err)
	}
	return r, tx.Commit(ctx)
}

func (d *Database) RevokeMachinePublicationPermission(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke machine publication permission", &retErr)()
	if err = closeMachinePublicationRuns(ctx, tx, team, "", id, now); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE control.machine_publication_permissions SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND team_id=$2`, id, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}

// the caller holds the team mutation guard, so new sessions and runs cannot
// enter this set. lock every parent before closing any run, taking routing
// clocks or locking the machine for key rotation. provisioning-enrolled
// publishers have their own lifetime and are not selected by this relation.
func closeMachinePublicationRuns(ctx context.Context, tx pgx.Tx, team, machine, permission string, now time.Time) error {
	if machine == "" && permission == "" {
		return ErrMachineDenied
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT session.publisher_identity_id,session.grant_id
		FROM control.machine_publication_sessions session
		JOIN control.publisher_identities publisher ON publisher.id=session.publisher_identity_id AND publisher.team_id=$1
		JOIN control.publish_runs run ON run.publisher_identity_id=session.publisher_identity_id AND run.publisher_grant_id=session.grant_id AND run.closed_at IS NULL
		WHERE ($2='' OR session.machine_id=$2) AND ($3='' OR session.permission_id=$3)
		ORDER BY session.publisher_identity_id,session.grant_id`, team, machine, permission)
	if err != nil {
		return err
	}
	type publication struct{ publisher, grant string }
	var publications []publication
	for rows.Next() {
		var p publication
		if err = rows.Scan(&p.publisher, &p.grant); err != nil {
			rows.Close()
			return err
		}
		publications = append(publications, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range publications {
		if err = lockPublisherPublications(ctx, tx, team, p.publisher, p.grant); err != nil {
			return err
		}
	}
	q := controlstatedb.New(tx)
	for _, p := range publications {
		if err = closeRevokedPublicPublications(ctx, tx, q, p.publisher, p.grant, now); err != nil {
			return err
		}
	}
	return nil
}

func machinePublicationNamespace(ctx context.Context, tx pgx.Tx, namespace string, now time.Time) error {
	var reserved bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE group_id IS NOT NULL AND (retired_at IS NULL OR reusable_after>$2) AND (namespace=$1 OR right(namespace,length($1)+1)='.'||$1 OR right($1,length(namespace)+1)='.'||namespace))`, namespace, now).Scan(&reserved)
	if err != nil {
		return err
	}
	if reserved {
		return ErrMachineDenied
	}
	return nil
}

func machinePublicationResource(ctx context.Context, tx pgx.Tx, id, hostname string, now time.Time) error {
	var managed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.applied_project_services WHERE public_url_id=$1 AND group_id IS NOT NULL)`, id).Scan(&managed); err != nil {
		return err
	}
	if managed {
		return ErrMachineDenied
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE group_id IS NOT NULL AND (retired_at IS NULL OR reusable_after>$2) AND (namespace=$1 OR right($1,length(namespace)+1)='.'||namespace))`, hostname, now).Scan(&managed); err != nil {
		return err
	}
	if managed {
		return ErrMachineDenied
	}
	return nil
}

type MachinePublicationExchange struct {
	MachineID, Resource, Namespace, Nonce string
	PublicKey                             ed25519.PublicKey
	Signature                             []byte
	Proof                                 MachineProof
}

type MachinePublicationSession = authorityv1.MachinePublicationSession

type machinePublicationAuthority struct {
	id, machine, permission, publisher, key, grant, resource, namespace, domain, membership, scope string
	revision                                                                                       int64
	proofExpiry, expiry                                                                            time.Time
}

func (d *Database) ExchangeMachinePublication(ctx context.Context, r MachinePublicationExchange, audience string, now time.Time) (result MachinePublicationSession, retErr error) {
	if (r.Resource == "") == (r.Namespace == "") || !workloadproof.ValidNonce(r.Nonce) || len(r.PublicKey) != 32 || len(r.Signature) != 64 {
		return result, ErrMachineDenied
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "exchange machine publication", &retErr)()
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.machine_identities WHERE id=$1`, r.MachineID).Scan(&team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	m, err := machineIdentity(ctx, tx, r.MachineID)
	if err != nil {
		return result, err
	}
	public := base64.RawURLEncoding.EncodeToString(r.PublicKey)
	until, digest, err := verifyMachineProof(ctx, tx, m, r.Proof, machineproof.Publication(r.Resource, r.Namespace, "exchange", public, r.Nonce), audience, clock.current())
	if err != nil {
		return result, err
	}
	assertion := sha256.Sum256([]byte(r.Proof.Assertion))
	if !ed25519.Verify(r.PublicKey, machineproof.PublicationPossession(r.Resource, r.Namespace, "exchange", public, r.Nonce, assertion), r.Signature) {
		return result, ErrMachineDenied
	}
	a := machinePublicationAuthority{machine: m.ID, resource: r.Resource, namespace: r.Namespace, revision: m.Revision}
	err = tx.QueryRow(ctx, `SELECT id,COALESCE(domain_id,''),COALESCE(membership_id,''),COALESCE(public_url_scope,''),expires_at FROM control.machine_publication_permissions WHERE machine_id=$1 AND team_id=$2 AND revoked_at IS NULL AND expires_at>$3 AND ((public_url_id=$4 AND $4<>'') OR (namespace=$5 AND $5<>'')) FOR UPDATE`, m.ID, team, clock.current(), r.Resource, r.Namespace).Scan(&a.permission, &a.domain, &a.membership, &a.scope, &a.expiry)
	if err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	permissionExpiry := a.expiry
	a.proofExpiry = minTime(until, a.expiry)
	var resolved resolvedPublisherScope
	if r.Resource != "" {
		u, e := q.LockPublicURLForRun(ctx, r.Resource)
		if e != nil {
			return result, publisherLookupError(e, ErrMachineDenied)
		}
		if u.TeamID != team || u.Purpose != "app" || u.Ephemeral || u.ServiceProtocol != "http" || u.LifecycleState != "enabled" {
			return result, ErrMachineDenied
		}
		if e = machinePublicationResource(ctx, tx, u.ID, u.CanonicalHostname, clock.current()); e != nil {
			return result, e
		}
		resolved = savedURLPublisherScope{team, r.Resource}
	} else {
		if err = machinePublicationNamespace(ctx, tx, r.Namespace, clock.current()); err != nil {
			return result, err
		}
		resolved = namespacePublisherScope{team, a.domain, r.Namespace, a.membership, PublicURLScope(a.scope)}
	}
	var existing, key, grant, permission string
	var saved []byte
	err = tx.QueryRow(ctx, `SELECT s.id,s.publisher_identity_id,s.key_id,s.grant_id,s.permission_id,k.public_key FROM control.machine_publication_sessions s JOIN control.publisher_identity_keys k ON k.id=s.key_id WHERE s.machine_id=$1 AND s.session_nonce=$2 FOR UPDATE OF s`, m.ID, r.Nonce).Scan(&existing, &a.publisher, &key, &grant, &permission, &saved)
	if err == nil {
		if !bytes.Equal(saved, r.PublicKey) || permission != a.permission {
			return result, ErrMachineDenied
		}
		a.id = existing
		a.key = key
		a.grant = grant
		// retries never extend source proof expiry. use the original session's
		// immutable authority; fresh assertions belong to the refresh endpoint.
		if err = tx.QueryRow(ctx, `SELECT proof_expires_at,expires_at,identity_revision FROM control.machine_publication_sessions WHERE id=$1`, a.id).Scan(&a.proofExpiry, &a.expiry, &a.revision); err != nil {
			return result, err
		}
		if a.revision != m.Revision {
			return result, ErrMachineDenied
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		var active int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.machine_publication_sessions WHERE machine_id=$1 AND proof_expires_at>$2 AND expires_at>$2`, m.ID, clock.current()).Scan(&active); err != nil {
			return result, err
		}
		if active >= 256 {
			return result, ErrMachineDenied
		}
		a.id, err = opaqueid.New("mps_")
		if err != nil {
			return result, err
		}
		p, e := insertPublisherForIssuer(ctx, q, resolved, "machine-publication", "automation", publisherIssuer{MachineID: m.ID}, "", "team", "", r.PublicKey, &a.expiry, now)
		if e != nil {
			return result, e
		}
		a.publisher = p.ID
		a.key = p.KeyID
		a.grant = p.GrantID
		if m.ProofKind == "signing_key" {
			if err = consumeMachineProof(ctx, tx, m.ID, digest, until); err != nil {
				return result, err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.machine_publication_sessions(id,machine_id,permission_id,identity_revision,publisher_identity_id,key_id,grant_id,session_nonce,created_at,refreshed_at,proof_expires_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11)`, a.id, m.ID, a.permission, m.Revision, a.publisher, a.key, a.grant, r.Nonce, now, a.proofExpiry, a.expiry)
		if err != nil {
			return result, err
		}
	} else {
		return result, err
	}
	originalDeadline := minTime(a.proofExpiry, minTime(a.expiry, permissionExpiry))
	result, err = d.machinePublicationSession(ctx, tx, a, clock.current())
	if err != nil {
		return result, err
	}
	// issuance may wait on the publisher after its authority-clock snapshot.
	// an idempotent retry must not commit a token past the saved session bounds
	// or the current permission deadline, even with a fresh exchange assertion.
	if !originalDeadline.After(clock.current()) {
		return MachinePublicationSession{}, ErrMachineDenied
	}
	return result, tx.Commit(ctx)
}

func (d *Database) machinePublicationSession(ctx context.Context, tx pgx.Tx, a machinePublicationAuthority, now time.Time) (r MachinePublicationSession, err error) {
	if !a.proofExpiry.After(now) || !a.expiry.After(now) {
		return r, ErrMachineDenied
	}
	q := controlstatedb.New(tx)
	p, g, err := d.livePublisher(ctx, q, a.publisher, a.grant, "", now)
	if err != nil {
		return r, err
	}
	access, err := d.issuePublisherAccess(ctx, tx, p, g, a.key, now, minTime(a.proofExpiry, a.expiry))
	if err != nil {
		return r, err
	}
	descriptor := authorityv1.PublisherEnrollmentResult{ClientId: p.ID, KeyId: a.key, GrantId: a.grant, TeamId: p.Scope.TeamID, Kind: authorityv1.PublisherEnrollmentResultKind(p.Scope.Kind)}
	if p.Scope.PublicURLID != "" {
		descriptor.PublicUrlId = new(p.Scope.PublicURLID)
	}
	if p.Scope.Namespace != "" {
		descriptor.Namespace = new(p.Scope.Namespace)
		descriptor.DomainId = new(p.Scope.DomainID)
	}
	return MachinePublicationSession{Id: a.id, Publisher: descriptor, AccessToken: access.Token, TokenType: "Bearer", ExpiresAt: access.Until, IdentityExpiresAt: a.proofExpiry, RenewAfter: minTime(now.Add(30*time.Second), a.proofExpiry.Add(-5*time.Second))}, nil
}

func machinePublisherDeadline(ctx context.Context, q *controlstatedb.Queries, publisher, grant string, now time.Time) (*time.Time, error) {
	r, err := q.MachinePublisherAuthority(ctx, controlstatedb.MachinePublisherAuthorityParams{PublisherIdentityID: publisher, GrantID: grant, NowTime: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !r.Allowed {
		return nil, ErrPublisherIdentity
	}
	if r.Deadline.Valid {
		return new(r.Deadline.Time), nil
	}
	return nil, nil
}

func boundMachineServingAuthority(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlPublishRun, now time.Time) (controlstatedb.ControlPublishRun, error) {
	if !run.PublisherIdentityID.Valid {
		return run, nil
	}
	deadline, err := machinePublisherDeadline(ctx, q, run.PublisherIdentityID.String, run.PublisherGrantID.String, now)
	if err != nil {
		return run, err
	}
	if deadline == nil || !deadline.Before(run.PublisherExpiresAt.Time) {
		return run, nil
	}
	return q.BoundMachinePublishRunExpiry(ctx, controlstatedb.BoundMachinePublishRunExpiryParams{ID: run.ID, Deadline: timestamptz(*deadline)})
}

// candidates come only from saved scope approvals. no issuer or JWKS address
// from an assertion is used for discovery, and this lookup is never exposed as
// a public policy response. fail closed rather than silently truncating trust.
type MachinePublicationLookup struct {
	Resource, Namespace, SessionID, MachineID string
	Hint                                      oidc.WorkloadIdentityHint
}

func (d *Database) MachinePublicationCandidates(ctx context.Context, lookup MachinePublicationLookup, now time.Time) (result []MachineIdentity, retErr error) {
	rows, err := d.pool.Query(ctx, `SELECT DISTINCT m.id FROM control.machine_identities m JOIN control.machine_publication_permissions p ON p.machine_id=m.id AND p.team_id=m.team_id LEFT JOIN control.machine_publication_sessions s ON s.permission_id=p.id WHERE m.revoked_at IS NULL AND p.revoked_at IS NULL AND p.expires_at>$4 AND (($3<>'' AND s.id=$3) OR ($3='' AND (($1<>'' AND p.public_url_id=$1) OR ($2<>'' AND p.namespace=$2)) AND (($5<>'' AND m.id=$5) OR ($5='' AND m.proof_kind='oidc' AND m.trust->>'issuer'=$6 AND m.trust->>'audience'=$7 AND m.trust->'claims'->>'sub'=$8)))) ORDER BY m.id LIMIT 9`, lookup.Resource, lookup.Namespace, lookup.SessionID, now, lookup.MachineID, lookup.Hint.Issuer, lookup.Hint.Audience, lookup.Hint.Subject)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > 8 {
		return nil, ErrMachineDenied
	}
	for _, id := range ids {
		m, err := d.MachineIdentityPolicy(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, nil
}

func (d *Database) RefreshMachinePublication(ctx context.Context, id string, proof MachineProof, signature []byte, audience string, now time.Time) (result MachinePublicationSession, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "refresh machine publication", &retErr)()
	var team string
	if err = tx.QueryRow(ctx, `SELECT m.team_id FROM control.machine_publication_sessions s JOIN control.machine_identities m ON m.id=s.machine_id WHERE s.id=$1`, id).Scan(&team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	a := machinePublicationAuthority{id: id}
	var public []byte
	var permissionExpiry time.Time
	err = tx.QueryRow(ctx, `SELECT s.machine_id,s.permission_id,s.identity_revision,s.publisher_identity_id,s.key_id,s.grant_id,s.proof_expires_at,s.expires_at,k.public_key,COALESCE(p.public_url_id,''),COALESCE(p.namespace,''),p.expires_at FROM control.machine_publication_sessions s JOIN control.publisher_identity_keys k ON k.id=s.key_id AND k.retired_at IS NULL JOIN control.machine_publication_permissions p ON p.id=s.permission_id AND p.revoked_at IS NULL AND p.expires_at>$2 WHERE s.id=$1 FOR UPDATE OF s`, id, clock.current()).Scan(&a.machine, &a.permission, &a.revision, &a.publisher, &a.key, &a.grant, &a.proofExpiry, &a.expiry, &public, &a.resource, &a.namespace, &permissionExpiry)
	if err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	originalDeadline := minTime(a.proofExpiry, minTime(a.expiry, permissionExpiry))
	if !originalDeadline.After(clock.current()) {
		return result, ErrMachineDenied
	}
	m, err := machineIdentity(ctx, tx, a.machine)
	if err != nil {
		return result, err
	}
	if m.Revision != a.revision {
		return result, ErrMachineDenied
	}
	encoded := base64.RawURLEncoding.EncodeToString(public)
	until, digest, err := verifyMachineProof(ctx, tx, m, proof, machineproof.Publication(a.resource, a.namespace, "refresh", encoded, id), audience, clock.current())
	if err != nil {
		return result, err
	}
	assertion := sha256.Sum256([]byte(proof.Assertion))
	if !ed25519.Verify(public, machineproof.PublicationPossession(a.resource, a.namespace, "refresh", encoded, id, assertion), signature) {
		return result, ErrMachineDenied
	}
	if m.ProofKind == "signing_key" {
		if err = consumeMachineProof(ctx, tx, m.ID, digest, until); err != nil {
			return result, err
		}
	}
	// a fresh proof may extend only authority that survived the work and waits
	// needed to verify it. retain the old deadline until issuance also finishes.
	if !originalDeadline.After(clock.current()) {
		return result, ErrMachineDenied
	}
	a.proofExpiry = minTime(maxTime(a.proofExpiry, until), a.expiry)
	if _, err = tx.Exec(ctx, `UPDATE control.machine_publication_sessions SET proof_expires_at=$2,refreshed_at=$3 WHERE id=$1`, id, a.proofExpiry, now); err != nil {
		return result, err
	}
	result, err = d.machinePublicationSession(ctx, tx, a, clock.current())
	if err != nil {
		return result, err
	}
	if !originalDeadline.After(clock.current()) {
		return MachinePublicationSession{}, ErrMachineDenied
	}
	return result, tx.Commit(ctx)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// retiring the publisher before removing its source relation is essential:
// otherwise deleting expired session state would turn its key into an ordinary
// unbounded publisher. the team gate also serializes cleanup with fresh proofs.
func (d *Database) cleanupMachinePublications(ctx context.Context, now time.Time, limit int) (removed int64, retErr error) {
	rows, err := d.pool.Query(ctx, `SELECT s.id FROM control.machine_publication_sessions s WHERE s.proof_expires_at<$1
		AND NOT EXISTS(SELECT 1 FROM control.publisher_namespace_allocations a JOIN control.public_urls u ON u.id=a.public_url_id
			WHERE a.publisher_identity_id=s.publisher_identity_id AND a.publisher_grant_id=s.grant_id AND u.lifecycle_state<>'deleted')
		ORDER BY s.proof_expires_at,s.id LIMIT $2`, now.Add(-WorkloadHistoryRetention), limit)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return removed, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return removed, err
	}
	for _, id := range ids {
		err = func() (retErr error) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer rollback(ctx, tx, "clean up machine publication", &retErr)()
			var team string
			if err = tx.QueryRow(ctx, `SELECT m.team_id FROM control.machine_publication_sessions s JOIN control.machine_identities m ON m.id=s.machine_id WHERE s.id=$1`, id).Scan(&team); errors.Is(err, pgx.ErrNoRows) {
				return nil
			} else if err != nil {
				return err
			}
			if _, err = controlstatedb.New(tx).LockMachinePublicationCleanupTeam(ctx, team); err != nil {
				return err
			}
			var publisher string
			if err = tx.QueryRow(ctx, `SELECT s.publisher_identity_id FROM control.machine_publication_sessions s WHERE s.id=$1 AND s.proof_expires_at<$2
				AND NOT EXISTS(SELECT 1 FROM control.publisher_namespace_allocations a JOIN control.public_urls u ON u.id=a.public_url_id
					WHERE a.publisher_identity_id=s.publisher_identity_id AND a.publisher_grant_id=s.grant_id AND u.lifecycle_state<>'deleted')
				FOR UPDATE OF s`, id, now.Add(-WorkloadHistoryRetention)).Scan(&publisher); errors.Is(err, pgx.ErrNoRows) {
				return nil
			} else if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`, publisher, now); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM control.publisher_access_tokens WHERE publisher_identity_id=$1`, publisher); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM control.machine_publication_sessions WHERE id=$1`, id); err != nil {
				return err
			}
			if err = tx.Commit(ctx); err == nil {
				removed++
			}
			return err
		}()
		if err != nil {
			return removed, err
		}
	}
	return removed, nil
}
