package controlstate

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// both ingress rechecks and publisher certificate checks use this decision. the
// first certificate check binds a direct admission; later checks cannot change
// its identity, device, key or original connection metadata.
func recheckDirectServiceVisitor(ctx context.Context, tx pgx.Tx, service, run string, number int64, visitor, identity, device string, source netip.Addr, certificateDigest []byte, now time.Time) (result PrivateVisitorValidity, err error) {
	result.ValidUntil = now
	var session string
	err = tx.QueryRow(ctx, `SELECT COALESCE(cert.control_session_id,'') FROM control.service_client_certificates cert LEFT JOIN control.direct_service_visitors v ON v.visitor_connection_id=$1 WHERE cert.certificate_digest=COALESCE($2::bytea,v.certificate_digest) AND cert.private_service_id=$3 AND cert.identity_id=$4 AND cert.device_id=$5 AND cert.revoked_at IS NULL AND cert.expires_at>$6`, visitor, certificateDigest, service, identity, device, now).Scan(&session)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: identity, SessionID: session})
	accessUntil, _, err := privateVisitorAccess(ctx, tx, service, identity, now)
	if err != nil {
		return result, err
	}
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT v.promoted_at IS NOT NULL,LEAST($9::timestamptz+interval '2 minutes',run.publisher_expires_at,run.certificate_expires_at,g.expires_at,ingress.lease_expires_at,cert.expires_at,
	    (SELECT max(relay.lease_expires_at) FROM control.private_service_connection_slots slot JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id WHERE slot.private_run_id=run.id AND slot.state='ready' AND slot.session_open AND relay.lease_expires_at>$9 AND NOT relay.draining))
	    FROM control.direct_service_visitors v JOIN control.private_services service ON service.id=v.private_service_id AND service.public AND service.enabled AND service.deleted_at IS NULL AND service.service_port=v.destination_port
	    JOIN control.private_service_runs run ON run.id=v.private_run_id AND run.private_service_id=service.id AND run.run_number=v.run_number AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$9 AND run.certificate_expires_at>$9
	    JOIN control.ingress_leases ingress ON ingress.ingress_id=v.ingress_id AND ingress.ingress_run_id=v.ingress_run_id AND ingress.ingress_lease_revision=v.ingress_lease_revision AND ingress.lease_expires_at>$9
	    JOIN control.publisher_grants g ON g.id=run.publisher_grant_id AND g.kind='private_service' AND g.private_service_id=service.id AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$9)
	    JOIN control.publisher_identities p ON p.id=run.publisher_identity_id AND p.id=g.publisher_identity_id AND p.revoked_at IS NULL
	    JOIN control.service_client_certificates cert ON cert.certificate_digest=COALESCE($8::bytea,v.certificate_digest) AND cert.private_service_id=service.id AND cert.identity_id=$5 AND cert.device_id=$6 AND cert.revoked_at IS NULL AND cert.expires_at>$9
	    JOIN control.visitor_devices device ON device.id=cert.device_id AND device.identity_id=cert.identity_id AND device.revoked_at IS NULL
	    WHERE v.visitor_connection_id=$1 AND v.private_service_id=$2 AND v.private_run_id=$3 AND v.run_number=$4 AND v.source_ip=$7 AND v.closed_at IS NULL AND v.valid_until>$9
	    AND(v.identity_id IS NULL OR v.identity_id=$5) AND(v.device_id IS NULL OR v.device_id=$6) AND(v.certificate_digest IS NULL OR v.certificate_digest=cert.certificate_digest)
	    AND EXISTS(SELECT 1 FROM control.private_service_connection_slots slot JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id WHERE slot.private_run_id=run.id AND slot.state='ready' AND slot.session_open AND relay.lease_expires_at>$9 AND NOT relay.draining)`, visitor, service, run, number, identity, device, source.Unmap(), certificateDigest, now).Scan(&result.Admitted, &deadline)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	deadline = minTime(deadline, accessUntil)
	if !deadline.After(now) {
		return result, nil
	}
	_, err = tx.Exec(ctx, `UPDATE control.direct_service_visitors SET identity_id=$2,device_id=$3,certificate_digest=COALESCE(certificate_digest,$4::bytea),http_credential_kind=NULL,http_credential_digest=NULL,valid_until=$5 WHERE visitor_connection_id=$1`, visitor, identity, device, certificateDigest, deadline)
	result.Allowed, result.ValidUntil = err == nil, deadline
	return result, err
}
