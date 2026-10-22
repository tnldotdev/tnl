package controlstate

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func managedHTTPDigest(kind, secret string) ([]byte, error) {
	if kind == "browser" {
		return browserDigest(secret)
	}
	if kind != "token" && kind != "share" {
		return nil, ErrPrivateServiceAccess
	}
	id, raw, ok := strings.Cut(secret, ".")
	if !ok || !opaqueid.Valid(id, "mhg_") {
		return nil, ErrPrivateServiceAccess
	}
	// the digest covers the complete scoped credential, including its grant ID.
	if _, err := browserDigest(raw); err != nil {
		return nil, ErrPrivateServiceAccess
	}
	return hashManagedHTTPSecret(secret), nil
}

func managedHTTPCredentialPermission(ctx context.Context, tx pgx.Tx, service, run, kind string, digest []byte, now time.Time) (time.Time, error) {
	if kind == "browser" {
		permission, err := managedBrowserPermission(ctx, tx, service, run, digest, now)
		if err != nil {
			return time.Time{}, err
		}
		if !permission.VisitAllowed || permission.ExpiresAt == nil {
			return time.Time{}, ErrPrivateServiceAccess
		}
		return *permission.ExpiresAt, nil
	}
	if kind != "token" && kind != "share" {
		return time.Time{}, ErrPrivateServiceAccess
	}
	grant, err := controlstatedb.New(tx).ManagedHTTPGrantPermission(ctx, controlstatedb.ManagedHTTPGrantPermissionParams{PrivateServiceID: service, Kind: kind, SecretDigest: digest, Now: timestamptz(now)})
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: grant.CreatedByIdentityID, SessionID: grant.ControlSessionID.String})
	until, _, err := privateVisitorAccess(ctx, tx, service, grant.CreatedByIdentityID, now)
	return minTime(until, grant.ExpiresAt.Time), err
}

func (d *Database) recheckManagedHTTPVisitor(ctx context.Context, tx pgx.Tx, service, run string, number int64, visitor string, source netip.Addr, port int32, kind string, digest []byte, now time.Time) (result PrivateVisitorValidity, err error) {
	result.ValidUntil = now
	q := controlstatedb.New(tx)
	if err := d.managedHTTPSourceAllowed(ctx, q, service, source); err != nil {
		return result, err
	}
	binding, err := q.ManagedHTTPDirectBinding(ctx, controlstatedb.ManagedHTTPDirectBindingParams{PrivateServiceID: service, PrivateRunID: run, RunNumber: number, VisitorConnectionID: visitor, SourceIp: source.Unmap(), DestinationPort: port, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	until, err := managedHTTPCredentialPermission(ctx, tx, service, run, kind, digest, now)
	if err != nil {
		return result, err
	}
	until = minTime(until, binding.ValidUntil.Time)
	if !until.After(now) {
		return result, nil
	}
	err = q.BindManagedHTTPDirectCredential(ctx, controlstatedb.BindManagedHTTPDirectCredentialParams{VisitorConnectionID: visitor, Kind: text(kind), Digest: digest, ValidUntil: timestamptz(until)})
	result.Allowed, result.Admitted, result.ValidUntil = err == nil, binding.Admitted, until
	return result, err
}

func (d *Database) AuthorizeManagedHTTPVisitor(ctx context.Context, auth ManagedHTTPRun, input controlv1.ManagedHTTPVisitorRequest, now time.Time) (result PrivateVisitorValidity, retErr error) {
	result.ValidUntil = now
	source, err := netip.ParseAddr(input.SourceIp)
	if err != nil || source.Zone() != "" || source.Unmap().String() != input.SourceIp || !auth.valid() || input.RunNumber != auth.Number || !opaqueid.Valid(input.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) || input.DestinationPort < 1024 || input.DestinationPort > 65535 {
		return result, ErrPrivateServiceAccess
	}
	credential := input.Credential
	if credential.Kind == "certificate" {
		if credential.Secret != nil || credential.Certificate == nil {
			return result, ErrPrivateServiceAccess
		}
		// the certificate API verifies the issuer, exact service and proof-bound
		// identity/device. the run's protocol and observed port are checked here.
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			return result, err
		}
		defer rollback(ctx, tx, "check certificate HTTP subject", &retErr)()
		if err = d.lockManagedHTTPRun(ctx, tx, auth, now); err != nil {
			return result, err
		}
		_, err = controlstatedb.New(tx).ManagedHTTPDirectBinding(ctx, controlstatedb.ManagedHTTPDirectBindingParams{PrivateServiceID: auth.Subject.ID, PrivateRunID: auth.RunID, RunNumber: auth.Number, VisitorConnectionID: input.VisitorConnectionId, SourceIp: source, DestinationPort: int32(input.DestinationPort), Now: timestamptz(now)})
		if err != nil {
			return result, publisherLookupError(err, ErrPrivateServiceAccess)
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return d.AuthorizeServiceClientCertificate(ctx, auth.Subject.ID, auth.RunID, auth.Token.String(), input.VisitorConnectionId, auth.Number, source, *credential.Certificate, now)
	}
	if credential.Certificate != nil {
		return result, ErrPrivateServiceAccess
	}
	if credential.Kind == "none" && credential.Secret == nil {
		return result, nil
	}
	if credential.Secret == nil {
		return result, ErrPrivateServiceAccess
	}
	digest, err := managedHTTPDigest(string(credential.Kind), *credential.Secret)
	if err != nil {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize managed HTTP visitor", &retErr)()
	if err = d.lockManagedHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	result, err = d.recheckManagedHTTPVisitor(ctx, tx, auth.Subject.ID, auth.RunID, auth.Number, input.VisitorConnectionId, source, int32(input.DestinationPort), string(credential.Kind), digest, now)
	if errors.Is(err, ErrPrivateServiceAccess) || errors.Is(err, ErrVisitorSignIn) {
		return PrivateVisitorValidity{ValidUntil: now}, nil
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// IP restrictions narrow a managed service's visitor policy. the encrypted
// applied document never changes the group's network reachability or scope.
func (d *Database) managedHTTPSourceAllowed(ctx context.Context, q *controlstatedb.Queries, service string, source netip.Addr) error {
	settings, err := d.managedHTTPSettings(ctx, q, service)
	if err != nil {
		return err
	}
	if settings == nil || settings.Access == nil || len(settings.Access.IP) == 0 {
		return nil
	}
	for _, raw := range settings.Access.IP {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return ErrPrivateServiceAccess
		}
		if prefix.Contains(source.Unmap()) {
			return nil
		}
	}
	return ErrPrivateServiceAccess
}

func (d *Database) managedHTTPSettings(ctx context.Context, q *controlstatedb.Queries, service string) (*ProjectServicePublicURL, error) {
	row, err := q.ManagedHTTPAppliedConfiguration(ctx, text(service))
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
		return nil, ErrPrivateServiceAccess
	}
	return s.PublicURL, nil
}
