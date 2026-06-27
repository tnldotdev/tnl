package controlstate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/servicepki"
)

const (
	ServiceEnrollmentRoleIngress = servicepki.RoleIngress
	ServiceEnrollmentRoleRelay   = servicepki.RoleRelay

	serviceCertificateLifetime = time.Hour
	relayTransportRenewalLead  = 30 * time.Minute
)

var (
	ErrServiceEnrollmentTokenNotFound = errors.New("controlstate: service enrollment token not found")
	ErrServiceEnrollmentCredential    = errors.New("controlstate: invalid service enrollment credential")
	ErrServiceEnrollmentRequest       = errors.New("controlstate: invalid service enrollment request")
	ErrRelayServiceConflict           = errors.New("controlstate: relay service configuration conflicts with durable state")
)

// ServiceAuthority describes the durable private service CA without exposing its key.
type ServiceAuthority struct {
	CertificatePEM string
	Serial         string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// ServiceEnrollmentToken is the durable, nonsecret description of one enrollment token.
type ServiceEnrollmentToken struct {
	ID                  string
	Role                servicepki.Role
	RelayServiceID      string
	CreatedByIdentityID string
	CreatedAt           time.Time
	LastUsedAt          *time.Time
	LastUsedProcessID   string
	UseCount            uint64
	RevokedAt           *time.Time
	RevokedByIdentityID string
}

// CreatedServiceEnrollmentToken includes the one-time raw token value.
type CreatedServiceEnrollmentToken struct {
	EnrollmentToken ServiceEnrollmentToken
	Token           credentials.ServiceEnrollmentToken
}

// CreateServiceEnrollmentTokenRequest carries the administrator and optional relay-service scope.
type CreateServiceEnrollmentTokenRequest struct {
	Role            servicepki.Role
	RelayServiceID  string
	RelayAddress    string
	TLSServerName   string
	ActorIdentityID string
	AuditRequestID  string
	CreatedAt       time.Time
}

// RelayTransportMaterial is shared by the processes in one relay service.
type RelayTransportMaterial struct {
	CertificatePEM string
	PrivateKeyPEM  string
	ExpiresAt      time.Time
}

// ServiceEnrollmentRequest requests a certificate for a process-local key.
type ServiceEnrollmentRequest struct {
	Token      credentials.ServiceEnrollmentToken
	Role       servicepki.Role
	ProcessID  string
	CSRPEM     string
	EnrolledAt time.Time
}

// LocalServiceEnrollmentRequest requests an in-process identity without a
// service enrollment token. Relay fields define its durable logical service.
type LocalServiceEnrollmentRequest struct {
	Role           servicepki.Role
	ProcessID      string
	CSRPEM         string
	RelayServiceID string
	RelayAddress   string
	TLSServerName  string
	EnrolledAt     time.Time
}

// ServiceEnrollment contains a service certificate and stable role facts.
type ServiceEnrollment struct {
	Role                   servicepki.Role
	ProcessID              string
	RelayServiceID         string
	RelayAddress           string
	TLSServerName          string
	ServiceCertificatePEM  string
	TrustBundlePEM         string
	CertificateExpiresAt   time.Time
	RelayTransportMaterial *RelayTransportMaterial
}

// EnsureServiceAuthority transactionally initializes and validates the durable service CA.
func (d *Database) EnsureServiceAuthority(ctx context.Context, now time.Time) (ServiceAuthority, error) {
	authority, createdAt, err := d.ensureServiceAuthority(ctx, now)
	if err != nil {
		return ServiceAuthority{}, err
	}
	return ServiceAuthority{
		CertificatePEM: authority.CertificatePEM,
		Serial:         authority.Certificate.SerialNumber.Text(16),
		CreatedAt:      createdAt,
		ExpiresAt:      authority.Certificate.NotAfter,
	}, nil
}

// IssueInternalControlCertificate issues a short-lived private API server certificate.
func (d *Database) IssueInternalControlCertificate(
	ctx context.Context,
	role servicepki.Role,
	hostname string,
	now time.Time,
) (servicepki.IssuedKeyPair, error) {
	authority, _, err := d.ensureServiceAuthority(ctx, now)
	if err != nil {
		return servicepki.IssuedKeyPair{}, err
	}
	issued, err := servicepki.IssueInternalControlCertificate(authority, role, hostname, now, serviceCertificateLifetime)
	if err != nil {
		return servicepki.IssuedKeyPair{}, fmt.Errorf("controlstate: issue internal control certificate: %w", err)
	}
	return issued, nil
}

func (d *Database) ensureServiceAuthority(ctx context.Context, now time.Time) (servicepki.Authority, time.Time, error) {
	if err := d.requireOpen(); err != nil {
		return servicepki.Authority{}, time.Time{}, err
	}
	queries := controlstatedb.New(d.pool)
	stored, err := queries.GetServiceAuthority(ctx)
	if err == nil {
		return parseStoredServiceAuthority(
			stored.CertificatePem, stored.PrivateKeyDer, stored.CertificateSerial,
			stored.CreatedAt.Time, stored.ExpiresAt.Time, now,
		)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return servicepki.Authority{}, time.Time{}, fmt.Errorf("controlstate: get service authority: %w", err)
	}

	candidate, err := servicepki.GenerateAuthority(now)
	if err != nil {
		return servicepki.Authority{}, time.Time{}, err
	}
	storedCandidate, err := queries.InitializeServiceAuthority(ctx, controlstatedb.InitializeServiceAuthorityParams{
		CertificatePem: candidate.CertificatePEM, PrivateKeyDer: candidate.PrivateKeyDER,
		CertificateSerial: candidate.Certificate.SerialNumber.Text(16),
		CreatedAt:         timestamptz(now), ExpiresAt: timestamptz(candidate.Certificate.NotAfter),
	})
	if err != nil {
		return servicepki.Authority{}, time.Time{}, fmt.Errorf("controlstate: initialize service authority: %w", err)
	}
	return parseStoredServiceAuthority(
		storedCandidate.CertificatePem, storedCandidate.PrivateKeyDer, storedCandidate.CertificateSerial,
		storedCandidate.CreatedAt.Time, storedCandidate.ExpiresAt.Time, now,
	)
}

func parseStoredServiceAuthority(
	certificatePEM string,
	privateKeyDER []byte,
	serial string,
	createdAt, expiresAt, now time.Time,
) (servicepki.Authority, time.Time, error) {
	authority, err := servicepki.ParseAuthority(certificatePEM, privateKeyDER, now)
	if err != nil {
		return servicepki.Authority{}, time.Time{}, fmt.Errorf("controlstate: invalid durable service authority: %w", err)
	}
	if serial != authority.Certificate.SerialNumber.Text(16) || !expiresAt.Equal(authority.Certificate.NotAfter) || createdAt.IsZero() {
		return servicepki.Authority{}, time.Time{}, errors.New("controlstate: durable service authority metadata is invalid")
	}
	return authority, createdAt, nil
}

// CreateServiceEnrollmentToken creates a reusable token and stores only its verifier.
func (d *Database) CreateServiceEnrollmentToken(
	ctx context.Context,
	request CreateServiceEnrollmentTokenRequest,
) (result CreatedServiceEnrollmentToken, retErr error) {
	if err := validateCreateServiceEnrollmentToken(request); err != nil {
		return result, fmt.Errorf("%w: %v", ErrServiceEnrollmentRequest, err)
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	token, lookupID, digest, err := credentials.NewServiceEnrollmentToken()
	if err != nil {
		return result, err
	}
	id, err := opaqueid.New("service_enrollment_token_")
	if err != nil {
		return result, fmt.Errorf("controlstate: create service enrollment token identity: %w", err)
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: begin service enrollment token creation: %w", err)
	}
	defer rollback(ctx, tx, "create service enrollment token", &retErr)()
	queries := controlstatedb.New(tx)
	if request.Role == ServiceEnrollmentRoleRelay {
		_, err = queries.CreateRelayService(ctx, controlstatedb.CreateRelayServiceParams{
			RelayServiceID: request.RelayServiceID, RelayAddress: request.RelayAddress,
			TlsServerName: request.TLSServerName, CreatedAt: timestamptz(request.CreatedAt),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return result, ErrRelayServiceConflict
		}
		if err != nil {
			return result, fmt.Errorf("controlstate: create relay service: %w", err)
		}
	}
	stored, err := queries.CreateServiceEnrollmentToken(ctx, controlstatedb.CreateServiceEnrollmentTokenParams{
		ID: id, LookupID: lookupID.String(), TokenDigest: digest[:], Role: string(request.Role),
		RelayServiceID: nullableText(request.RelayServiceID), CreatedByIdentityID: request.ActorIdentityID,
		CreatedAt: timestamptz(request.CreatedAt),
	})
	if err != nil {
		return result, fmt.Errorf("controlstate: create service enrollment token: %w", err)
	}
	if err := queries.CreateServiceEnrollmentAdminAuditEvent(ctx, controlstatedb.CreateServiceEnrollmentAdminAuditEventParams{
		ActorIdentityID: text(request.ActorIdentityID), Actor: request.ActorIdentityID,
		RequestID: request.AuditRequestID, Operation: "service_enrollment_token.create",
		TargetID: id, OccurredAt: timestamptz(request.CreatedAt),
	}); err != nil {
		return result, fmt.Errorf("controlstate: audit service enrollment token creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: commit service enrollment token creation: %w", err)
	}
	result.EnrollmentToken = serviceEnrollmentTokenFromRow(stored)
	result.Token = token
	return result, nil
}

// ListServiceEnrollmentTokens returns nonsecret token metadata newest first.
func (d *Database) ListServiceEnrollmentTokens(ctx context.Context) ([]ServiceEnrollmentToken, error) {
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(d.pool).ListServiceEnrollmentTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list service enrollment tokens: %w", err)
	}
	result := make([]ServiceEnrollmentToken, len(rows))
	for index, row := range rows {
		result[index] = serviceEnrollmentTokenFromRow(row)
	}
	return result, nil
}

// RevokeServiceEnrollmentToken prevents future enrollment with one token.
func (d *Database) RevokeServiceEnrollmentToken(
	ctx context.Context,
	id, actorIdentityID, auditRequestID string,
	now time.Time,
) (result ServiceEnrollmentToken, retErr error) {
	if !validStateIdentifier(id) || !validStateIdentifier(actorIdentityID) || !validStateIdentifier(auditRequestID) {
		return result, ErrServiceEnrollmentRequest
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: begin service enrollment token revocation: %w", err)
	}
	defer rollback(ctx, tx, "revoke service enrollment token", &retErr)()
	queries := controlstatedb.New(tx)
	stored, err := queries.RevokeServiceEnrollmentToken(ctx, controlstatedb.RevokeServiceEnrollmentTokenParams{
		RevokedAt: timestamptz(now), RevokedByIdentityID: text(actorIdentityID), ID: id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceEnrollmentTokenNotFound
	}
	if err != nil {
		return result, fmt.Errorf("controlstate: revoke service enrollment token: %w", err)
	}
	if err := queries.CreateServiceEnrollmentAdminAuditEvent(ctx, controlstatedb.CreateServiceEnrollmentAdminAuditEventParams{
		ActorIdentityID: text(actorIdentityID), Actor: actorIdentityID, RequestID: auditRequestID,
		Operation: "service_enrollment_token.revoke", TargetID: id, OccurredAt: timestamptz(now),
	}); err != nil {
		return result, fmt.Errorf("controlstate: audit service enrollment token revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: commit service enrollment token revocation: %w", err)
	}
	return serviceEnrollmentTokenFromRow(stored), nil
}

// EnrollService signs a caller-owned key and records token use atomically.
func (d *Database) EnrollService(ctx context.Context, request ServiceEnrollmentRequest) (result ServiceEnrollment, retErr error) {
	lookupID, tokenDigest, err := credentials.ParseServiceEnrollmentToken(request.Token)
	if err != nil || request.EnrolledAt.IsZero() {
		return result, ErrServiceEnrollmentCredential
	}
	authority, _, err := d.ensureServiceAuthority(ctx, request.EnrolledAt)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: begin service enrollment: %w", err)
	}
	defer rollback(ctx, tx, "enroll service", &retErr)()
	queries := controlstatedb.New(tx)
	stored, err := queries.LockServiceEnrollmentToken(ctx, lookupID.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceEnrollmentCredential
	}
	if err != nil {
		return result, fmt.Errorf("controlstate: lock service enrollment token: %w", err)
	}
	if stored.RevokedAt.Valid || servicepki.Role(stored.Role) != request.Role || !credentials.SecretHashMatches(stored.TokenDigest, tokenDigest) {
		return result, ErrServiceEnrollmentCredential
	}
	result, serial, err := issueServiceEnrollment(
		ctx, queries, authority, request.Role, request.ProcessID, request.CSRPEM,
		stored.RelayServiceID.String, stored.RelayAddress.String, stored.TlsServerName.String, request.EnrolledAt,
	)
	if err != nil {
		return result, err
	}
	if err := queries.RecordServiceEnrollmentUse(ctx, controlstatedb.RecordServiceEnrollmentUseParams{
		LastUsedAt: timestamptz(request.EnrolledAt), LastUsedProcessID: text(request.ProcessID), ID: stored.ID,
	}); err != nil {
		return result, fmt.Errorf("controlstate: record service enrollment use: %w", err)
	}
	if err := queries.CreateServiceEnrollmentEvent(ctx, controlstatedb.CreateServiceEnrollmentEventParams{
		ServiceEnrollmentTokenID: stored.ID, Role: string(request.Role), ProcessID: request.ProcessID,
		RelayServiceID: stored.RelayServiceID, CertificateSerial: serial,
		CertificateExpiresAt: timestamptz(result.CertificateExpiresAt), OccurredAt: timestamptz(request.EnrolledAt),
	}); err != nil {
		return result, fmt.Errorf("controlstate: audit service enrollment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: commit service enrollment: %w", err)
	}
	return result, nil
}

// EnrollLocalService signs a process-local key for a role composed inside the
// control process. It intentionally has no token or enrollment audit event.
func (d *Database) EnrollLocalService(
	ctx context.Context,
	request LocalServiceEnrollmentRequest,
) (result ServiceEnrollment, retErr error) {
	if request.EnrolledAt.IsZero() || !validStateIdentifier(request.ProcessID) ||
		request.Role != ServiceEnrollmentRoleIngress && request.Role != ServiceEnrollmentRoleRelay {
		return result, ErrServiceEnrollmentRequest
	}
	if request.Role == ServiceEnrollmentRoleIngress {
		if request.RelayServiceID != "" || request.RelayAddress != "" || request.TLSServerName != "" {
			return result, ErrServiceEnrollmentRequest
		}
	} else if err := validateCreateServiceEnrollmentToken(CreateServiceEnrollmentTokenRequest{
		Role: request.Role, RelayServiceID: request.RelayServiceID,
		RelayAddress: request.RelayAddress, TLSServerName: request.TLSServerName,
		ActorIdentityID: "local", AuditRequestID: "local", CreatedAt: request.EnrolledAt,
	}); err != nil {
		return result, fmt.Errorf("%w: %v", ErrServiceEnrollmentRequest, err)
	}
	authority, _, err := d.ensureServiceAuthority(ctx, request.EnrolledAt)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: begin local service enrollment: %w", err)
	}
	defer rollback(ctx, tx, "enroll local service", &retErr)()
	queries := controlstatedb.New(tx)
	if request.Role == ServiceEnrollmentRoleRelay {
		_, err = queries.CreateRelayService(ctx, controlstatedb.CreateRelayServiceParams{
			RelayServiceID: request.RelayServiceID, RelayAddress: request.RelayAddress,
			TlsServerName: request.TLSServerName, CreatedAt: timestamptz(request.EnrolledAt),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return result, ErrRelayServiceConflict
		}
		if err != nil {
			return result, fmt.Errorf("controlstate: create local relay service: %w", err)
		}
	}
	result, _, err = issueServiceEnrollment(
		ctx, queries, authority, request.Role, request.ProcessID, request.CSRPEM,
		request.RelayServiceID, request.RelayAddress, request.TLSServerName, request.EnrolledAt,
	)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: commit local service enrollment: %w", err)
	}
	return result, nil
}

func issueServiceEnrollment(
	ctx context.Context,
	queries *controlstatedb.Queries,
	authority servicepki.Authority,
	role servicepki.Role,
	processID, csrPEM, relayServiceID, relayAddress, tlsServerName string,
	now time.Time,
) (ServiceEnrollment, string, error) {
	identity := servicepki.Identity{Role: role, ProcessID: processID, RelayServiceID: relayServiceID}
	issued, err := servicepki.SignServiceCSR(authority, identity, csrPEM, now, serviceCertificateLifetime)
	if err != nil {
		return ServiceEnrollment{}, "", fmt.Errorf("%w: %v", ErrServiceEnrollmentRequest, err)
	}
	result := ServiceEnrollment{
		Role: role, ProcessID: processID, RelayServiceID: relayServiceID,
		RelayAddress: relayAddress, TLSServerName: tlsServerName,
		ServiceCertificatePEM: issued.CertificatePEM, TrustBundlePEM: authority.CertificatePEM,
		CertificateExpiresAt: issued.ExpiresAt,
	}
	if role == ServiceEnrollmentRoleRelay {
		transport, err := relayTransportMaterial(ctx, queries, authority, relayServiceID, now)
		if err != nil {
			return ServiceEnrollment{}, "", err
		}
		result.RelayTransportMaterial = &transport
	}
	return result, issued.Serial, nil
}

func relayTransportMaterial(
	ctx context.Context,
	queries *controlstatedb.Queries,
	authority servicepki.Authority,
	relayServiceID string,
	now time.Time,
) (RelayTransportMaterial, error) {
	relayService, err := queries.LockRelayServiceTransport(ctx, relayServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayTransportMaterial{}, ErrServiceEnrollmentCredential
	}
	if err != nil {
		return RelayTransportMaterial{}, fmt.Errorf("controlstate: lock relay transport material: %w", err)
	}
	if relayService.TransportCertificatePem.Valid && relayService.TransportPrivateKeyPem.Valid &&
		relayService.TransportCertificateExpiresAt.Valid &&
		relayService.TransportCertificateExpiresAt.Time.After(now.Add(relayTransportRenewalLead)) {
		return RelayTransportMaterial{
			CertificatePEM: relayService.TransportCertificatePem.String,
			PrivateKeyPEM:  relayService.TransportPrivateKeyPem.String,
			ExpiresAt:      relayService.TransportCertificateExpiresAt.Time,
		}, nil
	}
	issued, err := servicepki.IssueRelayTransportCertificate(
		authority, relayService.TlsServerName, now, serviceCertificateLifetime,
	)
	if err != nil {
		return RelayTransportMaterial{}, err
	}
	relayService, err = queries.SetRelayServiceTransport(ctx, controlstatedb.SetRelayServiceTransportParams{
		TransportCertificatePem: text(issued.CertificatePEM), TransportPrivateKeyPem: text(issued.PrivateKeyPEM),
		TransportCertificateSerial: text(issued.Serial), TransportCertificateExpiresAt: timestamptz(issued.ExpiresAt),
		UpdatedAt: timestamptz(now), RelayServiceID: relayServiceID,
	})
	if err != nil {
		return RelayTransportMaterial{}, fmt.Errorf("controlstate: store relay transport material: %w", err)
	}
	return RelayTransportMaterial{
		CertificatePEM: relayService.TransportCertificatePem.String,
		PrivateKeyPEM:  relayService.TransportPrivateKeyPem.String,
		ExpiresAt:      relayService.TransportCertificateExpiresAt.Time,
	}, nil
}

func validateCreateServiceEnrollmentToken(request CreateServiceEnrollmentTokenRequest) error {
	if request.Role != ServiceEnrollmentRoleIngress && request.Role != ServiceEnrollmentRoleRelay {
		return errors.New("controlstate: service enrollment role is invalid")
	}
	if !validStateIdentifier(request.ActorIdentityID) || !validStateIdentifier(request.AuditRequestID) || request.CreatedAt.IsZero() {
		return errors.New("controlstate: service enrollment token audit identity is invalid")
	}
	if request.Role == ServiceEnrollmentRoleIngress {
		if request.RelayServiceID != "" || request.RelayAddress != "" || request.TLSServerName != "" {
			return errors.New("controlstate: ingress enrollment token cannot have relay service scope")
		}
		return nil
	}
	if !validStateIdentifier(request.RelayServiceID) || !validStateIdentifier(request.RelayAddress) || !validStateIdentifier(request.TLSServerName) {
		return errors.New("controlstate: relay enrollment token requires relay service scope")
	}
	host, port, err := net.SplitHostPort(request.RelayAddress)
	canonical, canonicalErr := naming.CanonicalizeHostname(request.TLSServerName)
	if err != nil || port != "443" || host != request.TLSServerName || canonicalErr != nil || canonical != request.TLSServerName {
		return errors.New("controlstate: relay address or TLS server name is invalid")
	}
	return nil
}

func serviceEnrollmentTokenFromRow(row controlstatedb.ControlServiceEnrollmentToken) ServiceEnrollmentToken {
	return ServiceEnrollmentToken{
		ID: row.ID, Role: servicepki.Role(row.Role), RelayServiceID: row.RelayServiceID.String,
		CreatedByIdentityID: row.CreatedByIdentityID, CreatedAt: row.CreatedAt.Time,
		LastUsedAt: timePointer(row.LastUsedAt), LastUsedProcessID: row.LastUsedProcessID.String,
		UseCount: uint64(row.UseCount), RevokedAt: timePointer(row.RevokedAt),
		RevokedByIdentityID: row.RevokedByIdentityID.String,
	}
}

func timePointer(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func validStateIdentifier(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}
