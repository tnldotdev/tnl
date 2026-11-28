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
	if len(keys) == 0 {
		return result, ErrVisitorPolicy
	}
	policy := controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, Issuer: issuer,
		VisitorPolicyRevision: revision, KeyRevision: keyRevision, ObservedAt: now, ValidUntil: now.Add(d.servingTolerance()), VerificationKeys: []controlv1.VisitorVerificationKey{}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, RegisteredKeyLeases: []controlv1.VisitorRegisteredKeyLease{}}
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
	if row.Public {
		policy.PublicEndpoint = &controlv1.VisitorPublicEndpoint{
			Hostname: row.CertificateHostname, Port: int(row.ServicePort.Int32), EndpointRevision: row.EndpointRevision,
		}
	}
	policy.Enabled = row.Enabled && !row.DeletedAt.Valid && (!row.ExpiresAt.Valid || row.ExpiresAt.Time.After(now))
	if row.ExpiresAt.Valid && row.ExpiresAt.Time.After(now) {
		policy.ValidUntil = minTime(policy.ValidUntil, row.ExpiresAt.Time)
	}
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
		rows, err := tx.Query(ctx, `SELECT session.id,session.public_key,LEAST(session.lease_expires_at,session.expires_at,session.identity_expires_at,$3::timestamptz)
		    FROM control.workload_sessions session JOIN control.workload_session_services selected ON selected.workload_session_id=session.id
		    WHERE selected.service_id=$1 AND session.revoked_at IS NULL AND session.created_at<=$2 AND session.lease_expires_at>$2 AND session.identity_expires_at>$2 AND (session.expires_at IS NULL OR session.expires_at>$2) ORDER BY session.id`, scope.ID, now, now.Add(WorkloadLease))
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
		policy.RegisteredKeyLeases, err = readVisitorPolicyRegisteredKeys(ctx, q, scope.ID, now)
		if err != nil {
			return result, err
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

func readVisitorPolicyRegisteredKeys(ctx context.Context, q *controlstatedb.Queries, serviceID string, now time.Time) ([]controlv1.VisitorRegisteredKeyLease, error) {
	leases := []controlv1.VisitorRegisteredKeyLease{}
	// the candidate check is a subset of the joins in the full lookup.
	// only a negative answer matters, and both reads use the same snapshot.
	possible, err := q.HasVisitorPolicyRegisteredKeyCandidates(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	if !possible {
		return leases, nil
	}
	keys, err := q.ReadVisitorPolicyRegisteredKeys(ctx, controlstatedb.ReadVisitorPolicyRegisteredKeysParams{
		ServiceID: serviceID, AtTime: timestamptz(now),
	})
	if err != nil {
		return nil, err
	}
	leases = make([]controlv1.VisitorRegisteredKeyLease, 0, len(keys))
	for _, key := range keys {
		if !key.ExpiresAt.Valid {
			return nil, ErrVisitorPolicy
		}
		digest, err := visitortoken.KeyDigest(ed25519.PublicKey(key.PublicKey))
		if err != nil {
			return nil, err
		}
		leases = append(leases, controlv1.VisitorRegisteredKeyLease{
			GrantId: key.GrantID, KeyId: key.KeyID, KeySha256: digest, ExpiresAt: key.ExpiresAt.Time,
		})
	}
	return leases, nil
}

func (d *Database) ReadPublisherVisitorPolicy(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, after int64, now time.Time, hostnames ...string) (controlv1.VisitorPolicyUpdate, error) {
	hostname, err := serviceHTTPHostnameSelection(hostnames)
	if err != nil {
		return controlv1.VisitorPolicyUpdate{}, ErrVisitorPolicy
	}
	// retry a rolled-back observation with fresh time and current run authority.
	// this never replays a credential redemption or an application admission.
	return retryVisitorPreparation(ctx, now, func(at time.Time) (controlv1.VisitorPolicyUpdate, error) {
		return d.readPublisherVisitorPolicyTransaction(ctx, scope, run, number, token, after, at, hostname)
	})
}

func (d *Database) readPublisherVisitorPolicyTransaction(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, after int64, now time.Time, hostname string) (result controlv1.VisitorPolicyUpdate, retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read publisher visitor policy", &retErr)()
	q := controlstatedb.New(tx)
	if scope.Kind != visitorscope.Service {
		return result, ErrVisitorPolicy
	}
	if err := lockPublisherVisitorPolicy(ctx, tx, scope.ID); err != nil {
		return result, err
	}
	row, err := d.serviceRunObservationAuthorization(ctx, tx, q, scope.ID, run, token, now)
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
	// endpoint edits do not change this publisher's connector TLS identity.
	// current policy and target trust still apply to the captured run.
	result.Policy.Hostname = row.CertificateHostname
	if hostname != "" && hostname != row.CertificateHostname {
		var authorized bool
		if err := tx.QueryRow(ctx, `SELECT control.service_run_alias_current($1,$2)`,
			row.ID, hostname).Scan(&authorized); err != nil {
			return result, err
		}
		if hostname != row.RunHostname || !authorized || result.Policy.PublicEndpoint == nil {
			return result, ErrServiceAccess
		}
		result.Policy.Hostname = hostname
		result.Policy.PublicEndpoint.Hostname = hostname
	}
	result.Policy.ValidUntil = minTime(result.Policy.ValidUntil, row.ServingUntil.Time)
	if row.CertificateExpiresAt.Valid {
		result.Policy.ValidUntil = minTime(result.Policy.ValidUntil, row.CertificateExpiresAt.Time)
	}
	if result.Policy.Enabled {
		confirmations, err := d.policyConfirmations(ctx, q, row, now)
		if err != nil {
			return result, err
		}
		if confirmation := confirmations.forHost(result.Policy.Hostname); confirmation != nil && !confirmation.ValidUntil.After(result.Policy.ValidUntil) {
			result.ConfirmationKey = &confirmation.ConfirmationKey
		}
	}
	return result, tx.Commit(ctx)
}
