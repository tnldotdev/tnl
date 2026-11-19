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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func serviceCertificatePlan(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, publisher, grant string, now time.Time) (CertificatePlan, error) {
	if service.CertificateHostname == "" || service.CertificateScope == "" || !service.DomainID.Valid {
		return CertificatePlan{}, ErrCertificateIssuanceInvalid
	}
	if _, err := controlstatedb.New(tx).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: service.DomainID.String, TeamID: service.TeamID}); err != nil {
		return CertificatePlan{}, publisherLookupError(err, ErrServiceAccess)
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT g.kind FROM control.publisher_grants g
		WHERE g.id=$1 AND g.publisher_identity_id=$2
		AND EXISTS(SELECT 1 FROM control.publisher_service_permission($2,$1,$3,$4))`, grant, publisher, service.ID, now).Scan(&kind); err != nil {
		return CertificatePlan{}, publisherLookupError(err, ErrServiceAccess)
	}
	scope := service.CertificateScope
	if kind == DeploymentCredentialGrant {
		scope = service.CertificateHostname
	}
	if scope != service.CertificateHostname {
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1
		    FROM control.applied_project_services assignment
		    JOIN control.deployments g ON g.id=assignment.deployment_id AND g.deleted_at IS NULL
		    JOIN control.deployment_publisher_members member ON member.deployment_id=g.id
		    JOIN control.service_namespace_claims claim ON claim.deployment_id=g.id
		      AND claim.namespace=$3 AND claim.retired_at IS NULL
		    WHERE assignment.service_id=$1 AND member.publisher_identity_id=$2
		      AND (claim.namespace=g.namespace OR (claim.namespace=$4 AND claim.domain_id=$5)))`,
			service.ID, publisher, scope, service.RunAliasParent, service.DomainID).Scan(&allowed); err != nil {
			return CertificatePlan{}, err
		}
		if !allowed {
			return CertificatePlan{}, ErrServiceAccess
		}
	}
	plan := authorization.ServiceCertificatePlan(service.CertificateHostname, scope, false, true)
	if plan == nil || !certificateidentity.Covers(plan.Identifiers, service.CertificateHostname) {
		return CertificatePlan{}, ErrCertificateIssuanceInvalid
	}
	return CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: slices.Clone(plan.Identifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}, nil
}

// the run captured this plan under publisher and namespace authority at
// preparation. a public endpoint edit does not replace that connector identity;
// current publisher permission and domain authority still bound every renewal.
func serviceRunCertificatePlan(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun) (CertificatePlan, error) {
	if !run.CertificateDomainID.Valid {
		return CertificatePlan{}, ErrServiceAccess
	}
	if _, err := controlstatedb.New(tx).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{
		ID: run.CertificateDomainID.String, TeamID: run.TeamID,
	}); err != nil {
		return CertificatePlan{}, publisherLookupError(err, ErrServiceAccess)
	}
	plan := authorization.ServiceCertificatePlan(run.CertificateHostname, run.CertificateScope, false, true)
	if plan == nil {
		return CertificatePlan{}, ErrServiceAccess
	}
	captured := certificatePlanWithRunAlias(CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: slices.Clone(plan.Identifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}, run.CertificateHostname, run.RunHostname)
	if captured.CacheKey != run.CertificateCacheKey || captured.Scope != run.CertificateScope ||
		!slices.Equal(captured.Identifiers, run.CertificateIdentifiers) || !certificateidentity.Covers(captured.Identifiers, run.CertificateHostname) {
		return CertificatePlan{}, ErrServiceAccess
	}
	return captured, nil
}

// an alias never broadens a narrow publisher plan to its parent's wildcard.
// exact SANs keep the plan within the two approved names when a wildcard cannot
// be reused. the distinct cache key prevents mixing plans across runs.
func certificatePlanWithRunAlias(plan CertificatePlan, hostname, alias string) CertificatePlan {
	if alias == "" || certificateidentity.Covers(plan.Identifiers, alias) {
		return plan
	}
	identifiers := []string{hostname, alias}
	slices.Sort(identifiers)
	digest := sha256.Sum256([]byte(identifiers[0] + "\x00" + identifiers[1]))
	return CertificatePlan{CacheKey: "run-alias/" + hex.EncodeToString(digest[:]), Scope: hostname,
		Identifiers: identifiers, ChallengeMethod: certificateidentity.ChallengeDNS01}
}

func (d *Database) CreateServiceCertificateIssuance(ctx context.Context, service, runID, token, directory, key string, number int64, der []byte, now time.Time) (result CertificateIssuance, retErr error) {
	clock := newAuthorizationClock(now)
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
	run, err := d.serviceRunAuthorization(ctx, tx, q, service, runID, token, clock.current())
	if err != nil {
		return result, err
	}
	if run.RunNumber != number || len(run.CertificateIdentifiers) == 0 || run.SuppliedCertificateSha256.Valid {
		return result, ErrServiceAccess
	}
	if _, err = serviceRunCertificatePlan(ctx, tx, run); err != nil {
		return result, err
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
		order, err = q.GetServiceCertificateOrderByCSR(ctx, controlstatedb.GetServiceCertificateOrderByCSRParams{PublisherIdentityID: run.PublisherIdentityID, AccountID: account.ID, CsrDigest: csrDigest[:], CertificateCacheKey: run.CertificateCacheKey, CertificateScope: run.CertificateScope, CertificateIdentifiers: run.CertificateIdentifiers, DomainID: run.CertificateDomainID})
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
		if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: run.TeamID.String, ServiceID: service, ServiceKind: "service", EventType: "certificate.issue", RunID: runID, PublisherIdentityID: run.PublisherIdentityID, OccurredAt: now}, id); err != nil {
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
	if err = authorizeServiceCertificateOrder(ctx, tx, run, run.CertificateDomainID.String, order); err != nil {
		return result, err
	}
	created := result.NewOrder
	result, err = loadCertificateIssuance(ctx, q, order, now)
	if err != nil {
		return result, err
	}
	result.NewOrder = created
	if created {
		kind, kindErr := q.GetManagedCertificateDomainKind(ctx, run.CertificateDomainID.String)
		if kindErr != nil {
			return result, kindErr
		}
		result.DomainKind = DomainKind(kind)
	}
	result.PublisherIdentityID = run.PublisherIdentityID
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return CertificateIssuance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return CertificateIssuance{}, err
	}
	return result, nil
}

func (d *Database) GetServiceCertificateIssuance(ctx context.Context, service, runID, token, issuance string, now time.Time) (result CertificateIssuance, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get managed certificate issuance", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, service, runID, token, clock.current())
	if err != nil {
		return result, err
	}
	order, err := q.GetACMEOrder(ctx, issuance)
	if err != nil {
		return result, publisherLookupError(err, ErrCertificateIssuanceNotFound)
	}
	if err = authorizeServiceCertificateOrder(ctx, tx, run, run.CertificateDomainID.String, order); err != nil {
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
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return CertificateIssuance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return CertificateIssuance{}, err
	}
	return result, nil
}

func (d *Database) MarkServiceCertificateInstalled(ctx context.Context, service, runID, token, issuance string, number int64, notAfter, now time.Time) (retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "install managed certificate", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, service, runID, token, clock.current())
	if err != nil {
		return err
	}
	if run.RunNumber != number || run.SuppliedCertificateSha256.Valid {
		return ErrServiceAccess
	}
	if _, err = serviceRunCertificatePlan(ctx, tx, run); err != nil {
		return err
	}
	order, err := q.LockACMEOrder(ctx, issuance)
	if err != nil {
		return publisherLookupError(err, ErrCertificateIssuanceNotFound)
	}
	if err = authorizeServiceCertificateOrder(ctx, tx, run, run.CertificateDomainID.String, order); err != nil {
		return err
	}
	if order.State != "waiting_for_install" && order.State != "installed" || !order.NotAfter.Time.Equal(notAfter) || !validInstalledCertificate(order, run.CertificateHostname, clock.current()) {
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
	if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: run.TeamID.String, ServiceID: service, ServiceKind: "service", EventType: "certificate.install", RunID: runID, PublisherIdentityID: run.PublisherIdentityID, OccurredAt: now}, runID+"/"+issuance); err != nil {
		return err
	}
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
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
	var publisher string
	var team, guest pgtype.Text
	if err := tx.QueryRow(ctx, `SELECT publisher_identity_id,team_id,guest_id FROM control.service_runs WHERE id=$1`, order.ServiceRunID).Scan(&publisher, &team, &guest); err != nil {
		return publisherLookupError(err, ErrCertificateIssuanceInvalid)
	}
	if publisher != run.PublisherIdentityID || team != run.TeamID || guest != run.GuestID {
		return ErrCertificateIssuanceInvalid
	}
	return nil
}
