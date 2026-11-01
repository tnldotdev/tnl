package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	controlvisitor "github.com/tnldotdev/tnl/internal/control/certificates/visitor"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type WorkloadService struct {
	ID             string                    `json:"id"`
	Service        string                    `json:"service"`
	Protocol       string                    `json:"protocol"`
	Endpoint       *ServiceEndpoint          `json:"endpoint"`
	KubernetesAuth *controlv1.KubernetesAuth `json:"kubernetes_auth,omitempty"`
}

func (d *Database) ListWorkloadServices(ctx context.Context, credential string, now time.Time) (result []WorkloadService, retErr error) {
	result = []WorkloadService{}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list workload services", &retErr)()
	id, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT s.id,r.service,s.protocol,s.certificate_hostname,s.service_port,s.public FROM control.workload_session_services r JOIN control.services s ON s.id=r.service_id AND s.enabled AND s.deleted_at IS NULL WHERE r.workload_session_id=$1 ORDER BY r.service`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s WorkloadService
		s.Endpoint = &ServiceEndpoint{}
		if err = rows.Scan(&s.ID, &s.Service, &s.Protocol, &s.Endpoint.Hostname, &s.Endpoint.Port, &s.Endpoint.Public); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range result {
		if result[i].Protocol == "kubernetes" {
			result[i].KubernetesAuth, err = d.visitorKubernetesAuth(ctx, controlstatedb.New(tx), result[i].ID)
			if err != nil {
				return nil, err
			}
		}
	}
	return result, tx.Commit(ctx)
}

func (d *Database) IssueWorkloadServiceClientCertificate(ctx context.Context, credential, service string, csrDER []byte, now time.Time) (result ServiceClientCertificate, retErr error) {
	var protocol string
	if err := d.pool.QueryRow(ctx, `SELECT protocol FROM control.services WHERE id=$1`, service).Scan(&protocol); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if protocol == "http" {
		issuer, err := controlstatedb.New(d.pool).ReadVisitorTokenIssuer(ctx)
		if err != nil {
			return result, err
		}
		return d.IssueVisitorClientCertificate(ctx, issuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service}, WorkloadTokenSource{Credential: credential}, csrDER, now)
	}
	csr, err := controlvisitor.ValidateCSR(csrDER)
	if err != nil {
		return result, ErrCertificateIssuanceInvalid
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue workload service certificate", &retErr)()
	id, err := lockWorkloadCredential(ctx, tx, credential, now)
	if err != nil {
		return result, err
	}
	_, _, err = VisitorSubjectAccess(ctx, tx, service, workloadSubject(id), now)
	if err != nil {
		return result, err
	}
	var public []byte
	var until time.Time
	if err = tx.QueryRow(ctx, `SELECT public_key,expires_at FROM control.workload_sessions WHERE id=$1`, id).Scan(&public, &until); err != nil {
		return result, err
	}
	key, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, public) {
		return result, ErrWorkloadDenied
	}
	digest := sha256.Sum256(csrDER)
	var certificate []byte
	err = tx.QueryRow(ctx, `SELECT certificate_pem,expires_at FROM control.workload_client_certificates WHERE workload_session_id=$1 AND service_id=$2 AND csr_digest=$3 AND expires_at>$4`, id, service, digest[:], now).Scan(&certificate, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		certificate, err = issuer.IssueWorkload(csrDER, service, id, until, now)
		if err != nil {
			return result, err
		}
		block, _ := pem.Decode(certificate)
		leaf, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return result, parseErr
		}
		certDigest := sha256.Sum256(leaf.Raw)
		result.ExpiresAt = leaf.NotAfter
		_, err = tx.Exec(ctx, `INSERT INTO control.workload_client_certificates(certificate_digest,workload_session_id,service_id,csr_digest,certificate_pem,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workload_session_id,service_id,csr_digest) DO UPDATE SET certificate_digest=EXCLUDED.certificate_digest,certificate_pem=EXCLUDED.certificate_pem,expires_at=EXCLUDED.expires_at`, certDigest[:], id, service, digest[:], certificate, result.ExpiresAt)
	}
	if err != nil {
		return result, err
	}
	if err = workloadAudit(ctx, tx, id, "certificate.issue", service, now); err != nil {
		return result, err
	}
	result.ServiceID, result.CertificatePEM, result.IssuerPEM = service, string(certificate), string(issuer.CertificatePEM())
	return result, tx.Commit(ctx)
}

// recheck uses the same run, publisher, ingress, relay and source constraints as
// human direct admission, then intersects them with the workload's live lease.
func recheckWorkloadPublicServiceVisitor(ctx context.Context, tx pgx.Tx, service, run string, number int64, visitor, session string, source netip.Addr, certificateDigest []byte, now time.Time) (result ServiceVisitorValidity, err error) {
	until, _, err := VisitorSubjectAccess(ctx, tx, service, workloadSubject(session), now)
	if err != nil {
		return result, err
	}
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT v.promoted_at IS NOT NULL,LEAST($8::timestamptz+interval '90 seconds',run.publisher_expires_at,run.certificate_expires_at,g.expires_at,ingress.lease_expires_at,cert.expires_at,
        (SELECT max(relay.lease_expires_at) FROM control.service_connection_slots slot JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open AND relay.lease_expires_at>$8 AND NOT relay.draining))
        FROM control.public_service_visitors v JOIN control.services s ON s.id=v.service_id AND s.public AND s.enabled AND s.deleted_at IS NULL AND s.service_port=v.destination_port
        JOIN control.service_runs run ON run.id=v.service_run_id AND run.service_id=s.id AND run.run_number=v.run_number AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$8 AND run.certificate_expires_at>$8
        JOIN control.ingress_leases ingress ON ingress.ingress_id=v.ingress_id AND ingress.ingress_run_id=v.ingress_run_id AND ingress.ingress_lease_revision=v.ingress_lease_revision AND ingress.lease_expires_at>$8
        JOIN control.publisher_grants g ON g.id=run.publisher_grant_id AND g.service_id=s.id AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$8)
        JOIN control.publisher_identities p ON p.id=run.publisher_identity_id AND p.id=g.publisher_identity_id AND p.revoked_at IS NULL
        JOIN control.workload_client_certificates cert ON cert.certificate_digest=COALESCE($7::bytea,v.certificate_digest) AND cert.service_id=s.id AND cert.workload_session_id=$5 AND cert.expires_at>$8
        WHERE v.visitor_connection_id=$1 AND v.service_id=$2 AND v.service_run_id=$3 AND v.run_number=$4 AND v.source_ip=$6 AND v.closed_at IS NULL AND v.valid_until>$8
        AND v.identity_id IS NULL AND v.device_id IS NULL AND (v.workload_session_id IS NULL OR v.workload_session_id=$5) AND(v.certificate_digest IS NULL OR v.certificate_digest=cert.certificate_digest)
        AND EXISTS(SELECT 1 FROM control.service_connection_slots slot JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open AND relay.lease_expires_at>$8 AND NOT relay.draining)`, visitor, service, run, number, session, source.Unmap(), certificateDigest, now).Scan(&result.Admitted, &deadline)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	deadline = minTime(deadline, until)
	_, err = tx.Exec(ctx, `UPDATE control.public_service_visitors SET workload_session_id=$2,certificate_digest=COALESCE(certificate_digest,$3::bytea),valid_until=$4 WHERE visitor_connection_id=$1`, visitor, session, certificateDigest, deadline)
	result.Allowed, result.ValidUntil = err == nil && deadline.After(now), deadline
	return result, err
}

// AuthenticateVisitorSubjectKey is the shared private credential seam for the
// transport adapter. workload sessions never borrow visitor_devices rows.
func AuthenticateVisitorSubjectKey(ctx context.Context, tx pgx.Tx, subject VisitorSubject, service string, now time.Time) (ed25519.PublicKey, time.Time, error) {
	until, _, err := VisitorSubjectAccess(ctx, tx, service, subject, now)
	if err != nil {
		return nil, until, err
	}
	var key []byte
	if subject.WorkloadSessionID != "" {
		err = tx.QueryRow(ctx, `SELECT public_key FROM control.workload_sessions WHERE id=$1`, subject.WorkloadSessionID).Scan(&key)
	} else {
		err = tx.QueryRow(ctx, `SELECT public_key FROM control.visitor_devices WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL`, subject.DeviceID, subject.IdentityID).Scan(&key)
	}
	return ed25519.PublicKey(key), until, err
}
