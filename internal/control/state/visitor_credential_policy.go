package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type visitorCertificatePolicyFact struct {
	serial, subjectDigest, identity, device, workload, parent string
	expires                                                   time.Time
}

// visitorCredentialLeases confirms exact issued credentials in the background.
// the common permission model still decides current rights. these observations
// never widen a signed source, extend its hard expiry, or admit a visitor by ID.
func (d *Database) visitorCredentialLeases(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, now time.Time) ([]controlv1.VisitorCredentialLease, error) {
	result := []controlv1.VisitorCredentialLease{}
	rows, err := tx.Query(ctx, `SELECT fact.serial,fact.subject_sha256,COALESCE(fact.identity_id,''),COALESCE(fact.device_id,''),COALESCE(fact.workload_session_id,''),COALESCE(fact.control_session_id,''),fact.expires_at
	    FROM control.visitor_certificate_facts fact WHERE fact.service_id=$1 AND fact.expires_at>$2
	    AND ((fact.identity_id IS NOT NULL AND EXISTS(SELECT 1 FROM control.service_client_certificates current WHERE current.certificate_digest=fact.certificate_digest AND current.service_id=fact.service_id AND current.device_id=fact.device_id AND current.csr_digest=fact.csr_digest AND current.revoked_at IS NULL))
	        OR (fact.workload_session_id IS NOT NULL AND EXISTS(SELECT 1 FROM control.workload_client_certificates current WHERE current.certificate_digest=fact.certificate_digest AND current.service_id=fact.service_id AND current.workload_session_id=fact.workload_session_id AND current.csr_digest=fact.csr_digest)))
	    ORDER BY fact.serial LIMIT 4097`, scope.ID, now)
	if err != nil {
		return nil, err
	}
	var certificates []visitorCertificatePolicyFact
	for rows.Next() {
		var fact visitorCertificatePolicyFact
		if err := rows.Scan(&fact.serial, &fact.subjectDigest, &fact.identity, &fact.device, &fact.workload, &fact.parent, &fact.expires); err != nil {
			rows.Close()
			return nil, err
		}
		certificates = append(certificates, fact)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(certificates) > 4096 {
		return nil, ErrVisitorPolicy
	}
	for _, fact := range certificates {
		principal := WithControlPrincipal(ctx, ControlPrincipal{IdentityID: fact.identity, SessionID: fact.parent})
		subject := tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: fact.identity, DeviceID: fact.device}
		if fact.workload != "" {
			subject = workloadSubject(fact.workload)
		}
		until, _, err := VisitorSubjectAccess(principal, tx, scope.ID, subject, now)
		if errors.Is(err, ErrServiceAccess) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if fact.parent != "" {
			deadline, err := visitorCredentialParentDeadline(ctx, tx, fact.identity, fact.parent, now)
			if errors.Is(err, ErrVisitorPermission) {
				continue
			}
			if err != nil {
				return nil, err
			}
			until = minTime(until, deadline)
		}
		result = append(result, controlv1.VisitorCredentialLease{Kind: "certificate", Id: fact.serial, SubjectSha256: fact.subjectDigest, ExpiresAt: minTime(until, fact.expires)})
	}
	rows, err = tx.Query(ctx, `SELECT id,created_by_identity_id,COALESCE(control_session_id,''),kind,expires_at FROM control.service_http_grants
	    WHERE service_id=$1 AND revoked_at IS NULL AND expires_at>$2 ORDER BY id LIMIT 4097`, scope.ID, now)
	if err != nil {
		return nil, err
	}
	type grantFact struct {
		id, creator, parent, kind string
		expires                   time.Time
	}
	var grants []grantFact
	for rows.Next() {
		var fact grantFact
		if err := rows.Scan(&fact.id, &fact.creator, &fact.parent, &fact.kind, &fact.expires); err != nil {
			rows.Close()
			return nil, err
		}
		grants = append(grants, fact)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(grants)+len(result) > 4096 {
		return nil, ErrVisitorPolicy
	}
	q := controlstatedb.New(tx)
	for _, fact := range grants {
		permission, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: "service", ResourceID: scope.ID, IdentityID: fact.creator, ControlSessionID: fact.parent, Now: timestamptz(now)})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		until := fact.expires
		if permission.ExpiresAt.Valid && permission.ExpiresAt.InfinityModifier == 0 {
			until = minTime(until, permission.ExpiresAt.Time)
		}
		if fact.parent != "" {
			deadline, err := visitorCredentialParentDeadline(ctx, tx, fact.creator, fact.parent, now)
			if errors.Is(err, ErrVisitorPermission) {
				continue
			}
			if err != nil {
				return nil, err
			}
			until = minTime(until, deadline)
		}
		_, digest, err := visitortoken.CredentialBinding(visitortoken.Grant{GrantID: fact.id, Kind: fact.kind})
		if err != nil {
			return nil, err
		}
		result = append(result, controlv1.VisitorCredentialLease{Kind: "grant", Id: fact.id, SubjectSha256: digest, ExpiresAt: until})
	}
	return result, nil
}

func visitorCredentialParentDeadline(ctx context.Context, tx pgx.Tx, identity, parent string, now time.Time) (time.Time, error) {
	session, err := controlstatedb.New(tx).GetVisitorParentSession(ctx, parent)
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrVisitorPermission)
	}
	if session.IdentityID != identity || session.RevokedAt.Valid || !session.AccessExpiresAt.Time.After(now) || !session.RefreshExpiresAt.Time.After(now) {
		return time.Time{}, ErrVisitorPermission
	}
	return minTime(session.AccessExpiresAt.Time, session.RefreshExpiresAt.Time), nil
}
