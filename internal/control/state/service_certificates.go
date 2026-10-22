package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func serviceCertificatePlan(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, publisher string, now time.Time) (CertificatePlan, error) {
	if service.CertificateHostname == "" || service.CertificateScope == "" || !service.DomainID.Valid {
		return CertificatePlan{}, ErrCertificateIssuanceInvalid
	}
	if _, err := controlstatedb.New(tx).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: service.DomainID.String, TeamID: text(service.TeamID)}); err != nil {
		return CertificatePlan{}, publisherLookupError(err, ErrServiceAccess)
	}
	if service.CertificateScope != service.CertificateHostname {
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.applied_project_services assignment JOIN control.project_publisher_groups g ON g.id=assignment.group_id AND g.deleted_at IS NULL JOIN control.publisher_group_members member ON member.group_id=g.id JOIN control.service_namespace_claims claim ON claim.group_id=g.id AND claim.namespace=g.namespace AND claim.retired_at IS NULL WHERE assignment.service_id=$1 AND member.publisher_identity_id=$2 AND g.namespace=$3)`, service.ID, publisher, service.CertificateScope).Scan(&allowed); err != nil {
			return CertificatePlan{}, err
		}
		if !allowed {
			return CertificatePlan{}, ErrServiceAccess
		}
	}
	plan := authorization.PublicURLCertificatePlan(service.CertificateHostname, service.CertificateScope, false, true)
	if plan == nil || !certificateidentity.Covers(plan.Identifiers, service.CertificateHostname) {
		return CertificatePlan{}, ErrCertificateIssuanceInvalid
	}
	return CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: slices.Clone(plan.Identifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}, nil
}

func (d *Database) CreateServiceCertificateIssuance(ctx context.Context, service, runID, token, directory, key string, number int64, der []byte, now time.Time) (result CertificateIssuance, retErr error) {
	csrDigest, err := validateCertificateCSR(directory, key, der)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create managed certificate issuance", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, service, runID, token, now)
	if err != nil {
		return result, err
	}
	if run.RunNumber != number || len(run.CertificateIdentifiers) == 0 {
		return result, ErrServiceAccess
	}
	row, err := q.LockService(ctx, service)
	if err != nil {
		return result, err
	}
	plan, err := serviceCertificatePlan(ctx, tx, row, run.PublisherIdentityID, now)
	if err != nil || row.DomainID.String != run.CertificateDomainID.String || row.CertificateHostname != run.CertificateHostname || row.ServicePort != run.ServicePort || plan.Scope != run.CertificateScope || plan.CacheKey != run.CertificateCacheKey || !slices.Equal(plan.Identifiers, run.CertificateIdentifiers) {
		return result, errors.Join(ErrServiceAccess, err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	names, err := canonicalCertificateIdentifiers(csr.DNSNames)
	if err != nil || !slices.Equal(names, run.CertificateIdentifiers) {
		return result, ErrCertificateIssuanceInvalid
	}
	account, err := q.GetACMEAccountByDirectory(ctx, directory)
	if err != nil {
		return result, publisherLookupError(err, ErrCertificateIssuanceInvalid)
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "managed-certificate/"+run.PublisherIdentityID+"/"+account.ID+"/"+hex.EncodeToString(csrDigest[:])); err != nil {
		return result, err
	}
	digest := sha256.Sum256(append([]byte(service+"\x00"+runID+"\x00"+directory+"\x00"), der...))
	request, err := q.GetServiceCertificateRequest(ctx, controlstatedb.GetServiceCertificateRequestParams{ServiceRunID: runID, IdempotencyKey: key})
	var order controlstatedb.ControlAcmeOrder
	if err == nil {
		if !bytes.Equal(request.RequestDigest, digest[:]) {
			return result, ErrCertificateIssuanceIdempotency
		}
		order, err = q.GetACMEOrder(ctx, request.IssuanceID)
		if err != nil {
			return result, publisherLookupError(err, ErrCertificateIssuanceNotFound)
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		order, err = q.GetServiceCertificateOrderByCSR(ctx, controlstatedb.GetServiceCertificateOrderByCSRParams{PublisherIdentityID: run.PublisherIdentityID, AccountID: account.ID, CsrDigest: csrDigest[:], CertificateCacheKey: run.CertificateCacheKey, CertificateScope: run.CertificateScope, CertificateIdentifiers: run.CertificateIdentifiers, DomainID: row.DomainID})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		enabled, err := q.LockCertificateIssuanceControl(ctx)
		if err != nil {
			return result, err
		}
		if !enabled {
			return result, ErrCertificateIssuanceGated
		}
		id, err := opaqueid.New(opaqueid.IssuancePrefix)
		if err != nil {
			return result, err
		}
		order, err = q.InsertServiceCertificateOrder(ctx, controlstatedb.InsertServiceCertificateOrderParams{ID: id, AccountID: account.ID, ServiceRunID: runID, IdempotencyKey: key, RequestDigest: digest[:], CsrDer: der, CsrDigest: csrDigest[:], Now: timestamptz(now)})
		if err != nil {
			return result, err
		}
		result.NewOrder = true
		if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: run.TeamID, ServiceID: service, ServiceKind: "service", EventType: "certificate.issue", RunID: runID, PublisherIdentityID: run.PublisherIdentityID, OccurredAt: now}, id); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	if request.IssuanceID == "" {
		if err = q.InsertServiceCertificateRequest(ctx, controlstatedb.InsertServiceCertificateRequestParams{ServiceRunID: runID, IdempotencyKey: key, RequestDigest: digest[:], IssuanceID: order.ID}); err != nil {
			return result, err
		}
	}
	if err = authorizeServiceCertificateOrder(ctx, tx, run, row.DomainID.String, order); err != nil {
		return result, err
	}
	created := result.NewOrder
	result, err = loadCertificateIssuance(ctx, q, order, now)
	if err != nil {
		return result, err
	}
	result.NewOrder = created
	if created {
		kind, kindErr := q.GetManagedCertificateDomainKind(ctx, row.DomainID.String)
		if kindErr != nil {
			return result, kindErr
		}
		result.DomainKind = DomainKind(kind)
	}
	result.PublisherIdentityID = run.PublisherIdentityID
	return result, tx.Commit(ctx)
}

func (d *Database) GetServiceCertificateIssuance(ctx context.Context, service, runID, token, issuance string, now time.Time) (result CertificateIssuance, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get managed certificate issuance", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, service, runID, token, now)
	if err != nil {
		return result, err
	}
	serviceRow, err := q.GetService(ctx, service)
	if err != nil {
		return result, err
	}
	order, err := q.GetACMEOrder(ctx, issuance)
	if err != nil {
		return result, publisherLookupError(err, ErrCertificateIssuanceNotFound)
	}
	if err = authorizeServiceCertificateOrder(ctx, tx, run, serviceRow.DomainID.String, order); err != nil {
		if errors.Is(err, ErrCertificateIssuanceInvalid) {
			return result, ErrCertificateIssuanceNotFound
		}
		return result, err
	}
	result, err = loadCertificateIssuance(ctx, q, order, now)
	if err != nil {
		return result, err
	}
	result.PublisherIdentityID = run.PublisherIdentityID
	return result, tx.Commit(ctx)
}

func (d *Database) MarkServiceCertificateInstalled(ctx context.Context, service, runID, token, issuance string, number int64, notAfter, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "install managed certificate", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, service, runID, token, now)
	if err != nil {
		return err
	}
	if run.RunNumber != number {
		return ErrServiceAccess
	}
	serviceRow, err := q.LockService(ctx, service)
	if err != nil {
		return err
	}
	plan, err := serviceCertificatePlan(ctx, tx, serviceRow, run.PublisherIdentityID, now)
	if err != nil || serviceRow.DomainID.String != run.CertificateDomainID.String || serviceRow.CertificateHostname != run.CertificateHostname || serviceRow.ServicePort != run.ServicePort || plan.Scope != run.CertificateScope || !slices.Equal(plan.Identifiers, run.CertificateIdentifiers) {
		return errors.Join(ErrServiceAccess, err)
	}
	order, err := q.LockACMEOrder(ctx, issuance)
	if err != nil {
		return publisherLookupError(err, ErrCertificateIssuanceNotFound)
	}
	if err = authorizeServiceCertificateOrder(ctx, tx, run, serviceRow.DomainID.String, order); err != nil {
		return err
	}
	if order.State != "waiting_for_install" && order.State != "installed" || !order.NotAfter.Time.Equal(notAfter) || !validInstalledCertificate(order, serviceRow.CertificateHostname, now) {
		return ErrCertificateIssuanceInvalid
	}
	if run.CertificateIssuanceID.Valid {
		current, err := q.GetACMEOrder(ctx, run.CertificateIssuanceID.String)
		if err != nil {
			return err
		}
		if current.CreatedRevision > order.CreatedRevision {
			return ErrCertificateIssuanceInvalid
		}
	}
	if _, err = q.MarkACMEOrderInstalled(ctx, controlstatedb.MarkACMEOrderInstalledParams{IssuanceID: issuance, InstalledAt: timestamptz(now)}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET certificate_issuance_id=$2,certificate_expires_at=$3 WHERE id=$1`, runID, issuance, notAfter); err != nil {
		return err
	}
	if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: run.TeamID, ServiceID: service, ServiceKind: "service", EventType: "certificate.install", RunID: runID, PublisherIdentityID: run.PublisherIdentityID, OccurredAt: now}, runID+"/"+issuance); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if run.CertificateIssuanceID.String != issuance {
		d.activity.metrics.Load().ObserveCertificateTransition("service", "installed")
	}
	return nil
}

func authorizeServiceCertificateOrder(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, domain string, order controlstatedb.ControlAcmeOrder) error {
	if order.ServiceRunID == "" || order.ChallengeMethod != "dns-01" || order.CertificateScope != run.CertificateScope || order.CertificateCacheKey != run.CertificateCacheKey || order.CertificateDomainID.String != domain || !slices.Equal(order.CertificateIdentifiers, run.CertificateIdentifiers) {
		return ErrCertificateIssuanceInvalid
	}
	var publisher, team string
	if err := tx.QueryRow(ctx, `SELECT publisher_identity_id,team_id FROM control.service_runs WHERE id=$1`, order.ServiceRunID).Scan(&publisher, &team); err != nil {
		return publisherLookupError(err, ErrCertificateIssuanceInvalid)
	}
	if publisher != run.PublisherIdentityID || team != run.TeamID {
		return ErrCertificateIssuanceInvalid
	}
	return nil
}
