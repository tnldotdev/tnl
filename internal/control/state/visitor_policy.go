package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrVisitorPolicy = errors.New("visitor policy is unavailable")

// readVisitorPolicy uses one repeatable-read snapshot for facts, their covered
// policy revision, and verification keys. no visitor operation calls this reader.
func (d *Database) readVisitorPolicy(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, after int64, now time.Time) (result controlv1.VisitorPolicyUpdate, err error) {
	if scope.Kind != visitorscope.Service || !scope.Valid() || after < 0 {
		return result, ErrVisitorPolicy
	}
	q := controlstatedb.New(tx)
	revision, err := q.ReadVisitorPolicyRevision(ctx, scope.ID)
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorPolicy)
	}
	if after > revision {
		return result, ErrVisitorPolicy
	}
	issuer, err := q.ReadVisitorTokenIssuer(ctx)
	if err != nil {
		return result, err
	}
	keyRevision, err := q.ReadVisitorVerificationKeyRevision(ctx)
	if err != nil {
		return result, err
	}
	keys, err := q.VisitorTokenVerificationKeys(ctx, timestamptz(now))
	if err != nil {
		return result, err
	}
	if len(keys) == 0 || len(keys) > maximumVisitorVerificationKeys {
		return result, ErrVisitorPolicy
	}
	policy := controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, Issuer: issuer,
		VisitorPolicyRevision: revision, KeyRevision: keyRevision, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime), VerificationKeys: []controlv1.VisitorVerificationKey{}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, RegisteredKeyLeases: []controlv1.VisitorRegisteredKeyLease{}}
	for _, key := range keys {
		policy.VerificationKeys = append(policy.VerificationKeys, controlv1.VisitorVerificationKey{Id: key.ID, PublicKey: key.PublicKey})
	}
	var prefixes []netip.Prefix
	ipRestricted := false
	team := ""
	guestID := ""
	row, err := q.ReadVisitorPolicyService(ctx, scope.ID)
	if err != nil {
		return result, err
	}
	if !row.ServicePort.Valid || !serviceendpoint.Valid(row.Protocol, row.CertificateHostname, int(row.ServicePort.Int32), row.Public) {
		return result, ErrVisitorPolicy
	}
	team, guestID, policy.Hostname, policy.Port = row.TeamID.String, row.GuestID.String, row.CertificateHostname, int(serviceendpoint.PermissionPort(row.Protocol))
	policy.MetadataRevision = row.TrustRevision
	policy.Enabled = row.Enabled && !row.DeletedAt.Valid && (!row.ExpiresAt.Valid || row.ExpiresAt.Time.After(now))
	settings, err := d.serviceHTTPSettings(ctx, q, scope.ID)
	if err != nil {
		return result, err
	}
	policy.Anonymous = settings != nil && settings.Access != nil && settings.Access.VisitorMode() == "anonymous"
	if settings != nil && settings.Access != nil && len(settings.Access.IP) > 0 {
		ipRestricted = true
		for _, raw := range settings.Access.IP {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return result, err
			}
			prefixes = append(prefixes, prefix)
		}
	}
	var activeTeam bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.teams WHERE id=$1 AND deleted_at IS NULL)`, team).Scan(&activeTeam); err != nil {
		return result, err
	}
	if guestID != "" {
		var guest bool
		var deadline time.Time
		err := tx.QueryRow(ctx, `SELECT control.guest_share_live(id,$2),control.guest_serving_deadline(id,$2)
		    FROM control.guest_trials WHERE id=$1`, guestID, now).Scan(&guest, &deadline)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		activeTeam = guest
		if err == nil {
			policy.ConnectionDeadline = &deadline
		}
		if err == nil && !deadline.After(now) {
			policy.Enabled = false
		} else if guest && deadline.Before(policy.ValidUntil) {
			policy.ValidUntil = deadline
		}
	}
	policy.Enabled = policy.Enabled && activeTeam
	if ipRestricted && policy.Ip == nil {
		key, err := d.storageKey.IPPolicyKey(d.storageKey.CurrentID(), "visitor-policy:"+string(scope.Kind)+":"+scope.ID)
		if err != nil {
			return result, err
		}
		ip := controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{}}
		for _, prefix := range prefixes {
			entry, err := ippolicy.Hash(key, prefix)
			if err != nil {
				return result, err
			}
			ip.Prefixes = append(ip.Prefixes, controlv1.HashedIPPrefix{Family: controlv1.HashedIPPrefixFamily(entry.Family), PrefixLength: entry.Bits, Digest: entry.Digest})
		}
		policy.Ip = &ip
	}
	if scope.Kind == visitorscope.Service {
		// a renewal may commit after the request clock but before this snapshot.
		// retain that current session, bounded by this observation's lease budget;
		// omitting it would revoke live streams when the publisher applies policy.
		rows, err := tx.Query(ctx, `SELECT session.id,session.public_key,LEAST(session.lease_expires_at,session.expires_at,session.identity_expires_at,$2::timestamptz+interval '90 seconds')
		    FROM control.workload_sessions session JOIN control.workload_session_services selected ON selected.workload_session_id=session.id
		    WHERE selected.service_id=$1 AND session.revoked_at IS NULL AND session.created_at<=$2 AND session.lease_expires_at>$2 AND session.identity_expires_at>$2 AND (session.expires_at IS NULL OR session.expires_at>$2) ORDER BY session.id LIMIT 4097`, scope.ID, now)
		if err != nil {
			return result, err
		}
		for rows.Next() {
			var id string
			var public []byte
			var until time.Time
			if err := rows.Scan(&id, &public, &until); err != nil {
				rows.Close()
				return result, err
			}
			digest, err := visitortoken.KeyDigest(ed25519.PublicKey(public))
			if err != nil {
				rows.Close()
				return result, err
			}
			policy.WorkloadLeases = append(policy.WorkloadLeases, controlv1.VisitorWorkloadLease{SessionId: id, KeySha256: digest, ExpiresAt: until})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, err
		}
		if len(policy.WorkloadLeases) > 4096 {
			return result, ErrVisitorPolicy
		}
		rows, err = tx.Query(ctx, `SELECT approval.grant_id,signing.id,current.public_key,current.expires_at
		    FROM control.applied_project_services binding
		    JOIN control.deployment_management_services selected ON selected.team_id=binding.team_id AND selected.project_key=binding.project_key AND selected.service=binding.service AND selected.capability='connect' AND selected.revoked_at IS NULL
		    JOIN control.deployment_management_grants approval ON approval.grant_id=selected.grant_id
		    JOIN control.publisher_grants grant_record ON grant_record.id=approval.grant_id
		    JOIN control.publisher_identity_keys signing ON signing.publisher_identity_id=grant_record.publisher_identity_id AND signing.retired_at IS NULL
		    CROSS JOIN LATERAL control.deployment_connect_authority(approval.grant_id,signing.id,$1,$2) current
		    WHERE binding.service_id=$1 ORDER BY approval.grant_id,signing.id LIMIT 4097`, scope.ID, now)
		if err != nil {
			return result, err
		}
		for rows.Next() {
			var lease controlv1.VisitorRegisteredKeyLease
			var public []byte
			if err = rows.Scan(&lease.GrantId, &lease.KeyId, &public, &lease.ExpiresAt); err != nil {
				rows.Close()
				return result, err
			}
			lease.KeySha256, err = visitortoken.KeyDigest(ed25519.PublicKey(public))
			if err != nil {
				rows.Close()
				return result, err
			}
			policy.RegisteredKeyLeases = append(policy.RegisteredKeyLeases, lease)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, err
		}
		if len(policy.RegisteredKeyLeases) > 4096 {
			return result, ErrVisitorPolicy
		}
	}
	events, err := q.ReadVisitorPolicyEvents(ctx, controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: scope.ID, AfterRevision: after})
	if err != nil {
		return result, err
	}
	result = controlv1.VisitorPolicyUpdate{Policy: policy, AfterRevision: after, Revisions: []int64{}, SnapshotRequired: after == 0}
	next := after
	for _, event := range events {
		if event.Revision != next+1 {
			result.SnapshotRequired = true
		}
		next = event.Revision
		result.Revisions = append(result.Revisions, event.Revision)
	}
	if next != revision {
		result.SnapshotRequired = true
	}
	if result.SnapshotRequired {
		result.Revisions = []int64{}
	}
	return result, nil
}

func (d *Database) ReadPublisherVisitorPolicy(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, after int64, now time.Time) (result controlv1.VisitorPolicyUpdate, retErr error) {
	// retry a rolled-back observation with fresh time and current run authority.
	// this never replays a credential redemption or an application admission.
	return retryVisitorPreparation(ctx, now, func(at time.Time) (controlv1.VisitorPolicyUpdate, error) {
		return d.readPublisherVisitorPolicyTransaction(ctx, scope, run, number, token, after, at)
	})
}

func (d *Database) readPublisherVisitorPolicyTransaction(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, after int64, now time.Time) (result controlv1.VisitorPolicyUpdate, retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read publisher visitor policy", &retErr)()
	q := controlstatedb.New(tx)
	if scope.Kind != visitorscope.Service {
		return result, ErrVisitorPolicy
	}
	if err := lockServiceAdmission(ctx, tx, scope.ID); err != nil {
		return result, err
	}
	row, err := d.serviceRunAuthorization(ctx, tx, q, scope.ID, run, token, now)
	if err != nil {
		return result, err
	}
	if row.RunNumber != number {
		return result, ErrServiceAccess
	}
	result, err = d.readVisitorPolicy(ctx, tx, scope, after, now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
