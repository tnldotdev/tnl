package state

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrVisitorPolicy = errors.New("visitor policy is unavailable")

// readVisitorPolicy uses one repeatable-read snapshot for facts, their covered
// policy revision, and verification keys. no visitor operation calls this reader.
func (d *Database) readVisitorPolicy(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, after int64, now time.Time) (result controlv1.VisitorPolicyUpdate, err error) {
	if !scope.Valid() || after < 0 {
		return result, ErrVisitorPolicy
	}
	q := controlstatedb.New(tx)
	revision, err := q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID})
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
		VisitorPolicyRevision: revision, KeyRevision: keyRevision, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime), VerificationKeys: []controlv1.VisitorVerificationKey{}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}
	for _, key := range keys {
		policy.VerificationKeys = append(policy.VerificationKeys, controlv1.VisitorVerificationKey{Id: key.ID, PublicKey: key.PublicKey})
	}
	var prefixes []netip.Prefix
	ipRestricted := false
	team := ""
	switch scope.Kind {
	case visitorscope.PublicURL:
		row, err := q.GetFeedbackPublicURL(ctx, scope.ID)
		if err != nil {
			return result, err
		}
		team, policy.Hostname, policy.Port = row.TeamID, row.CanonicalHostname, 443
		policy.Enabled = row.LifecycleState == "enabled" && (!row.ExpiresAt.Valid || row.ExpiresAt.Time.After(now))
		policy.Anonymous = row.AccessMode == "anonymous"
		if row.ExpiresAt.Valid && row.ExpiresAt.Time.After(now) && row.ExpiresAt.Time.Before(policy.ValidUntil) {
			policy.ValidUntil = row.ExpiresAt.Time
		}
		ipRestricted = row.IpPolicy != "allow_all"
		if ipRestricted {
			initialized, err := q.HasVisitorIPSet(ctx, scope.ID)
			if err != nil {
				return result, err
			}
			if initialized {
				grants, err := d.readVisitorIPs(ctx, q, scope.ID, now)
				if err != nil {
					return result, err
				}
				for _, grant := range grants {
					prefix, err := netip.ParsePrefix(grant.Prefix)
					if err != nil {
						return result, ErrVisitorPolicy
					}
					prefixes = append(prefixes, prefix)
					if grant.ExpiresAt != nil && grant.ExpiresAt.Before(policy.ValidUntil) {
						policy.ValidUntil = *grant.ExpiresAt
					}
				}
			} else if len(row.AllowedIpPolicyCiphertext) != 0 {
				prefixes, err = d.openIPPolicy(row.ID, row.AllowedIpPolicyStorageKeyID.String, row.AllowedIpPolicyCiphertext)
				if err != nil {
					return result, err
				}
			} else if len(row.AllowedIpHashes) != 0 {
				var entries []ippolicy.Entry
				if err := json.Unmarshal(row.AllowedIpHashes, &entries); err != nil {
					return result, ErrVisitorPolicy
				}
				key, err := d.storageKey.IPPolicyKey(row.AllowedIpHashKeyID.String, "url:"+scope.ID)
				if err != nil {
					return result, err
				}
				ip := controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{}}
				for _, entry := range entries {
					ip.Prefixes = append(ip.Prefixes, controlv1.HashedIPPrefix{Family: controlv1.HashedIPPrefixFamily(entry.Family), PrefixLength: entry.Bits, Digest: entry.Digest})
				}
				policy.Ip = &ip
			}
		}
	case visitorscope.Service:
		row, err := q.ReadVisitorPolicyService(ctx, scope.ID)
		if err != nil {
			return result, err
		}
		if !row.ServicePort.Valid || row.ServicePort.Int32 < 1024 || row.ServicePort.Int32 > 65535 {
			return result, ErrVisitorPolicy
		}
		team, policy.Hostname, policy.Port = row.TeamID, row.CertificateHostname, int(row.ServicePort.Int32)
		policy.Enabled = row.Enabled && !row.DeletedAt.Valid
		settings, err := d.serviceHTTPSettings(ctx, q, scope.ID)
		if err != nil {
			return result, err
		}
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
	}
	var activeTeam bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.teams WHERE id=$1 AND deleted_at IS NULL)`, team).Scan(&activeTeam); err != nil {
		return result, err
	}
	if scope.Kind == visitorscope.PublicURL {
		var guest bool
		var deadline time.Time
		err := tx.QueryRow(ctx, `SELECT control.guest_share_live(id,$2),LEAST(expires_at,
		    COALESCE(active_ready_at + (GREATEST(0,900000000000-used_ready_ns)::double precision/1000000000)*interval '1 second',expires_at))
		    FROM control.guest_trials WHERE team_id=$1`, team, now).Scan(&guest, &deadline)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		activeTeam = activeTeam || guest
		if guest && deadline.After(now) && deadline.Before(policy.ValidUntil) {
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
		rows, err := tx.Query(ctx, `SELECT session.id,session.public_key,LEAST(session.lease_expires_at,session.expires_at)
		    FROM control.workload_sessions session JOIN control.workload_session_services selected ON selected.workload_session_id=session.id
		    WHERE selected.service_id=$1 AND session.revoked_at IS NULL AND session.created_at<=$2 AND session.renewed_at<=$2 AND session.lease_expires_at>$2 AND session.expires_at>$2 ORDER BY session.id LIMIT 4097`, scope.ID, now)
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
	}
	events, err := q.ReadVisitorPolicyEvents(ctx, controlstatedb.ReadVisitorPolicyEventsParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID, AfterRevision: after})
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
	var sourceKey []byte
	switch scope.Kind {
	case visitorscope.PublicURL:
		// match mutation order before publisherRunLive takes identity/grant
		// guards. a background read must not reverse heartbeat's URL-first order.
		if _, err := lockVisitorURL(ctx, q, scope.ID); err != nil {
			return result, err
		}
		id, digest, err := credentials.ParsePublishRunToken(credentials.PublishRunToken(token))
		if err != nil {
			return result, ErrPublishRunCredential
		}
		row, err := q.GetPublishRun(ctx, run)
		if err != nil {
			return result, publisherLookupError(err, ErrPublishRunCredential)
		}
		if row.PublicURLID != scope.ID || row.PublishRunNumber != number || row.PublishRunTokenID != id.String() || !credentials.SecretHashMatches(row.PublishRunTokenDigest, digest) || row.ClosedAt.Valid || !row.PublisherExpiresAt.Time.After(now) || !slices.Contains([]string{"starting", "ready"}, row.State) {
			return result, ErrPublishRunCredential
		}
		url, err := q.GetFeedbackPublicURL(ctx, scope.ID)
		if err != nil {
			return result, err
		}
		if live, err := d.publisherRunLive(ctx, q, url, run, now); err != nil || !live {
			if err != nil {
				return result, err
			}
			return result, ErrPublishRunCredential
		}
		key, err := visitortoken.PublicVisitorSourceKey(row.PublishRunTokenDigest, run, uint64(number))
		if err != nil {
			return result, err
		}
		sourceKey = key[:]
	case visitorscope.Service:
		row, err := serviceRunAuthorization(ctx, tx, q, scope.ID, run, token, now)
		if err != nil {
			return result, err
		}
		if row.RunNumber != number {
			return result, ErrServiceAccess
		}
	default:
		return result, ErrVisitorPolicy
	}
	result, err = d.readVisitorPolicy(ctx, tx, scope, after, now)
	if err != nil {
		return result, err
	}
	if sourceKey != nil {
		result.VisitorSourceKey = &sourceKey
	}
	return result, tx.Commit(ctx)
}
