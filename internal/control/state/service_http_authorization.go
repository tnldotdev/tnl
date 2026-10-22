package state

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPCredentialKind string

const (
	serviceHTTPNone        serviceHTTPCredentialKind = "none"
	serviceHTTPBrowser     serviceHTTPCredentialKind = "browser"
	serviceHTTPToken       serviceHTTPCredentialKind = "token"
	serviceHTTPShare       serviceHTTPCredentialKind = "share"
	serviceHTTPCertificate serviceHTTPCredentialKind = "certificate"
)

func (kind serviceHTTPCredentialKind) secret() bool {
	return kind == serviceHTTPBrowser || kind.grant()
}

func (kind serviceHTTPCredentialKind) grant() bool {
	return kind == serviceHTTPToken || kind == serviceHTTPShare
}

// parsed HTTP credentials carry exactly one selected payload. only secret kinds
// can be restored from a stored digest; certificate verification stays with the
// certificate API and cannot fall back to a different supplied credential.
type serviceHTTPCredential struct {
	kind        serviceHTTPCredentialKind
	digest      [32]byte
	certificate []byte
}

func storedServiceHTTPCredential(kind string, digest []byte) (serviceHTTPCredential, error) {
	credential := serviceHTTPCredential{kind: serviceHTTPCredentialKind(kind)}
	if !credential.kind.secret() || len(digest) != len(credential.digest) {
		return serviceHTTPCredential{}, ErrServiceAccess
	}
	copy(credential.digest[:], digest)
	return credential, nil
}

func parseServiceHTTPCredential(input controlv1.ServiceHTTPCredential) (serviceHTTPCredential, error) {
	kind := serviceHTTPCredentialKind(input.Kind)
	switch kind {
	case serviceHTTPNone:
		if input.Secret == nil && input.Certificate == nil {
			return serviceHTTPCredential{kind: kind}, nil
		}
	case serviceHTTPCertificate:
		if input.Secret == nil && input.Certificate != nil {
			return serviceHTTPCredential{kind: kind, certificate: slices.Clone(*input.Certificate)}, nil
		}
	default:
		if kind.secret() && input.Secret != nil && input.Certificate == nil {
			digest, err := serviceHTTPDigest(string(kind), *input.Secret)
			if err != nil {
				return serviceHTTPCredential{}, ErrServiceAccess
			}
			return storedServiceHTTPCredential(string(kind), digest)
		}
	}
	return serviceHTTPCredential{}, ErrServiceAccess
}

func serviceHTTPDigest(kind, secret string) ([]byte, error) {
	selected := serviceHTTPCredentialKind(kind)
	if selected == serviceHTTPBrowser {
		return browserDigest(secret)
	}
	if !selected.grant() {
		return nil, ErrServiceAccess
	}
	id, raw, ok := strings.Cut(secret, ".")
	if !ok || !opaqueid.Valid(id, "shg_") {
		return nil, ErrServiceAccess
	}
	// the digest covers the complete scoped credential, including its grant ID.
	if _, err := browserDigest(raw); err != nil {
		return nil, ErrServiceAccess
	}
	return hashServiceHTTPSecret(secret), nil
}

func serviceHTTPCredentialPermission(ctx context.Context, tx pgx.Tx, service, run string, credential serviceHTTPCredential, now time.Time) (time.Time, error) {
	if credential.kind == serviceHTTPBrowser {
		permission, err := serviceBrowserPermission(ctx, tx, service, run, credential.digest[:], now)
		if err != nil {
			return time.Time{}, err
		}
		if !permission.VisitAllowed || permission.ExpiresAt == nil {
			return time.Time{}, ErrServiceAccess
		}
		return *permission.ExpiresAt, nil
	}
	if !credential.kind.grant() {
		return time.Time{}, ErrServiceAccess
	}
	grant, err := controlstatedb.New(tx).ServiceHTTPGrantPermission(ctx, controlstatedb.ServiceHTTPGrantPermissionParams{ServiceID: service, Kind: string(credential.kind), SecretDigest: credential.digest[:], Now: timestamptz(now)})
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrServiceAccess)
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: grant.CreatedByIdentityID, SessionID: grant.ControlSessionID.String})
	until, _, err := privateVisitorAccess(ctx, tx, service, grant.CreatedByIdentityID, now)
	return minTime(until, grant.ExpiresAt.Time), err
}

func (d *Database) recheckServiceHTTPVisitor(ctx context.Context, tx pgx.Tx, service, run string, number int64, visitor string, source netip.Addr, port int32, credential serviceHTTPCredential, now time.Time) (result ServiceVisitorValidity, err error) {
	result.ValidUntil = now
	q := controlstatedb.New(tx)
	if err := d.serviceHTTPSourceAllowed(ctx, q, service, source); err != nil {
		return result, err
	}
	binding, err := q.ServiceHTTPDirectBinding(ctx, controlstatedb.ServiceHTTPDirectBindingParams{ServiceID: service, ServiceRunID: run, RunNumber: number, VisitorConnectionID: visitor, SourceIp: source.Unmap(), DestinationPort: port, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	until, err := serviceHTTPCredentialPermission(ctx, tx, service, run, credential, now)
	if err != nil {
		return result, err
	}
	until = minTime(until, binding.ValidUntil.Time)
	if !until.After(now) {
		return result, nil
	}
	err = q.BindServiceHTTPDirectCredential(ctx, controlstatedb.BindServiceHTTPDirectCredentialParams{VisitorConnectionID: visitor, Kind: text(string(credential.kind)), Digest: credential.digest[:], ValidUntil: timestamptz(until)})
	result.Allowed, result.Admitted, result.ValidUntil = err == nil, binding.Admitted, until
	return result, err
}

func (d *Database) AuthorizeServiceHTTPVisitor(ctx context.Context, auth ServiceHTTPRun, input controlv1.ServiceHTTPVisitorRequest, now time.Time) (result ServiceVisitorValidity, retErr error) {
	result.ValidUntil = now
	source, err := netip.ParseAddr(input.SourceIp)
	if err != nil || source.Zone() != "" || source.Unmap().String() != input.SourceIp || !auth.valid() || input.RunNumber != auth.Number || !opaqueid.Valid(input.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) || input.DestinationPort < 1024 || input.DestinationPort > 65535 {
		return result, ErrServiceAccess
	}
	credential, err := parseServiceHTTPCredential(input.Credential)
	if err != nil {
		return result, err
	}
	if credential.kind == serviceHTTPCertificate {
		// the certificate API verifies the issuer, exact service and proof-bound
		// identity/device. the run's protocol and observed port are checked here.
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			return result, err
		}
		defer rollback(ctx, tx, "check certificate HTTP subject", &retErr)()
		if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
			return result, err
		}
		_, err = controlstatedb.New(tx).ServiceHTTPDirectBinding(ctx, controlstatedb.ServiceHTTPDirectBindingParams{ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, RunNumber: auth.Number, VisitorConnectionID: input.VisitorConnectionId, SourceIp: source, DestinationPort: int32(input.DestinationPort), Now: timestamptz(now)})
		if err != nil {
			return result, publisherLookupError(err, ErrServiceAccess)
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return d.AuthorizeServiceClientCertificate(ctx, auth.Subject.ID, auth.RunID, auth.Token.String(), input.VisitorConnectionId, auth.Number, source, credential.certificate, now)
	}
	if credential.kind == serviceHTTPNone {
		return result, nil
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize service HTTP visitor", &retErr)()
	if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	result, err = d.recheckServiceHTTPVisitor(ctx, tx, auth.Subject.ID, auth.RunID, auth.Number, input.VisitorConnectionId, source, int32(input.DestinationPort), credential, now)
	if errors.Is(err, ErrServiceAccess) || errors.Is(err, ErrVisitorSignIn) {
		return ServiceVisitorValidity{ValidUntil: now}, nil
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// IP restrictions narrow a service's visitor policy. the encrypted
// applied document never changes the group's network reachability or scope.
func (d *Database) serviceHTTPSourceAllowed(ctx context.Context, q *controlstatedb.Queries, service string, source netip.Addr) error {
	settings, err := d.serviceHTTPSettings(ctx, q, service)
	if err != nil {
		return err
	}
	if settings == nil || settings.Access == nil || len(settings.Access.IP) == 0 {
		return nil
	}
	for _, raw := range settings.Access.IP {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return ErrServiceAccess
		}
		if prefix.Contains(source.Unmap()) {
			return nil
		}
	}
	return ErrServiceAccess
}

func (d *Database) serviceHTTPSettings(ctx context.Context, q *controlstatedb.Queries, service string) (*config.HTTPService, error) {
	row, err := q.ServiceHTTPAppliedConfiguration(ctx, text(service))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c, err := d.openAppliedProject(controlstatedb.ControlAppliedProject{TeamID: row.TeamID, ProjectKey: row.ProjectKey, ConfigurationCiphertext: row.ConfigurationCiphertext, StorageKeyID: row.StorageKeyID})
	if err != nil {
		return nil, err
	}
	s, ok := c.Services[row.Service]
	if !ok {
		return nil, ErrServiceAccess
	}
	if err := config.ValidateGroupHTTP(s.HTTP); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	return s.HTTP, nil
}
