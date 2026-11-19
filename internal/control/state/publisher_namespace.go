package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func newEphemeralHostname(namespace string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", ErrProjectConfigurationInvalid
	}
	label, err := naming.RandomHostnameLabel()
	if err != nil {
		return "", err
	}
	host := label + "." + namespace
	if len(host) > naming.MaxHostnameBytes {
		return "", ErrProjectConfigurationInvalid
	}
	return host, nil
}

type AllocateServiceRequest struct {
	Invocation    string
	Configuration ProjectServiceConfiguration
	ExpiresAt     *time.Time
}

// normalize the caller's declaration, never operator-resolved defaults. both
// allocation paths persist this exact protected intent and share service runs.
func normalizeServiceAllocation(r AllocateServiceRequest) (ProjectServiceConfiguration, string, error) {
	var s ProjectServiceConfiguration
	data, err := json.Marshal(r.Configuration)
	if err != nil || len(data) > 512<<10 {
		return s, "", ErrProjectConfigurationInvalid
	}
	if err = json.Unmarshal(data, &s); err != nil {
		return s, "", errors.Join(ErrProjectConfigurationInvalid, err)
	}
	if s.Name == "" {
		s.Name = "temporary"
	}
	if s.Hostname != "" || s.DomainID != "" || s.TargetDiscovery != nil ||
		s.Access != nil || s.Public != nil && !*s.Public ||
		s.HTTP != nil && (len(s.HTTP.Paths) != 0 || s.HTTP.Readiness != nil ||
			s.HTTP.Access != nil && s.HTTP.Access.IP != nil && len(s.HTTP.Access.IP) == 0) {
		return s, "", ErrProjectConfigurationInvalid
	}
	s.Ephemeral, s.Public = true, new(true)
	if err = normalizeAppliedProjectService(s.Name, &s, savedServiceConfiguration); err != nil {
		return s, "", err
	}
	descriptor, err := appliedLocalTargetDescriptor(s.Target, s.Protocol)
	// app names an inline HTTP handler, not host discovery. allocations still
	// reject compose/docker descriptors and target TLS without a target socket.
	if err != nil || descriptor && s.Target != "app" || s.Target == "app" && s.TargetTLS != nil ||
		s.Protocol != "http" || !opaqueid.Valid(r.Invocation, opaqueid.InvocationPrefix) {
		return s, "", ErrProjectConfigurationInvalid
	}
	mode := "restricted"
	if s.HTTP != nil && s.HTTP.Access != nil {
		mode = s.HTTP.Access.VisitorMode()
	}
	return s, mode, nil
}

// allocation credentials must use the current key. they do not inherit exact
// service enrollment's retired-key recovery allowance.
func (d *Database) currentServiceAllocator(ctx context.Context, q *controlstatedb.Queries, p PublisherIdentity, now time.Time, lock bool) (PublisherIdentity, error) {
	identity, err := q.ReadPublisherIdentity(ctx, p.ID)
	if err == nil && lock {
		identity, err = q.LockPublisherIdentity(ctx, p.ID)
	}
	if err != nil {
		return PublisherIdentity{}, publisherLookupError(err, ErrPublisherIdentity)
	}
	grant, err := q.ReadPublisherGrant(ctx, controlstatedb.ReadPublisherGrantParams{ID: p.GrantID, PublisherIdentityID: p.ID})
	if err != nil {
		return PublisherIdentity{}, publisherLookupError(err, ErrPublisherIdentity)
	}
	current, err := d.currentPublisher(ctx, q, identity, grant, "", now)
	if err != nil {
		return current, err
	}
	key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: p.KeyID, PublisherIdentityID: p.ID})
	if err != nil {
		return current, publisherLookupError(err, ErrPublisherIdentity)
	}
	if key.RetiredAt.Valid || current.GuestID != "" {
		return current, ErrPublisherIdentity
	}
	current.KeyID = key.ID
	return current, nil
}

func (d *Database) AllocatePublisherService(ctx context.Context, p PublisherIdentity, r AllocateServiceRequest, now time.Time) (result ServiceRecord, retErr error) {
	if p.Scope.Kind != "namespace" || p.GuestID != "" {
		return result, ErrPublisherIdentity
	}
	s, mode, err := normalizeServiceAllocation(r)
	if err != nil {
		return result, err
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "allocate namespace service", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, p.Scope.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	// the team guard serializes retries, membership and namespace mutations.
	// only the allocation record can authorize recovery of an existing service.
	current, err := d.currentServiceAllocator(ctx, q, p, clock.current(), false)
	if err != nil {
		return result, err
	}
	if current.Scope.Kind != "namespace" {
		return result, ErrPublisherIdentity
	}
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: current.Scope.DomainID, TeamID: text(current.Scope.TeamID)})
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if domain.Kind == "custom" && !domain.DnsAuthorityReference.Valid {
		return result, ErrServiceAccess
	}
	// SQL checks the stored namespace's current domain and owner independently
	// of the issuing person's human management permissions.
	result, err = d.allocateService(ctx, tx, current, "", domain.ID, current.Scope.Namespace, r, s, mode, clock)
	if err != nil {
		return ServiceRecord{}, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = d.currentServiceAllocator(ctx, q, p, clock.current(), true); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, result.ID, clock.current()); err != nil {
		return ServiceRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}

func (d *Database) allocateService(ctx context.Context, tx pgx.Tx, p PublisherIdentity, deployment, domain, namespace string, r AllocateServiceRequest, s ProjectServiceConfiguration, mode string, clock authorizationClock) (ServiceRecord, error) {
	q := controlstatedb.New(tx)
	requestedExpiry := allocationDeadline(r.ExpiresAt)
	existing, err := q.FindPublisherAllocation(ctx, controlstatedb.FindPublisherAllocationParams{PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, InvocationID: r.Invocation})
	if err == nil {
		row, err := q.LockService(ctx, existing.ServiceID)
		if err != nil {
			return ServiceRecord{}, err
		}
		if _, err = d.currentServiceAllocator(ctx, q, p, clock.current(), true); err != nil {
			return ServiceRecord{}, err
		}
		if row.DeletedAt.Valid || !row.Enabled || row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(clock.current()) ||
			existing.DeploymentID.String != deployment || !sameAllocationDeadline(optionalTime(existing.RequestedExpiresAt), requestedExpiry) {
			return ServiceRecord{}, ErrServiceConflict
		}
		saved, err := d.serviceConfiguration(ctx, q, row.ID)
		if err != nil {
			return ServiceRecord{}, err
		}
		if saved == nil {
			return ServiceRecord{}, ErrServiceAccess
		}
		old, err := json.Marshal(saved)
		if err != nil {
			return ServiceRecord{}, err
		}
		intent, err := json.Marshal(s)
		if err != nil {
			return ServiceRecord{}, err
		}
		previous, requested := sha256.Sum256(old), sha256.Sum256(intent)
		if subtle.ConstantTimeCompare(previous[:], requested[:]) != 1 {
			return ServiceRecord{}, ErrServiceConflict
		}
		if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, row.ID, clock.current()); err != nil {
			return ServiceRecord{}, err
		}
		return d.publisherServiceRecord(ctx, tx, row)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ServiceRecord{}, err
	}
	grant, err := q.ReadPublisherGrant(ctx, controlstatedb.ReadPublisherGrantParams{ID: p.GrantID, PublisherIdentityID: p.ID})
	if err != nil {
		return ServiceRecord{}, err
	}
	until := optionalTime(grant.ExpiresAt)
	if requestedExpiry != nil && (until == nil || requestedExpiry.Before(*until)) {
		until = requestedExpiry
	}
	if until != nil && !until.After(clock.current()) {
		return ServiceRecord{}, ErrPublisherIdentity
	}
	if err := requireNewServiceWork(ctx, q, MaintenanceControlServiceCreation); err != nil {
		return ServiceRecord{}, err
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return ServiceRecord{}, err
	}
	ownership := sha256.Sum256([]byte(p.ID + "\x00" + p.GrantID + "\x00" + r.Invocation))
	if _, err = q.InsertService(ctx, controlstatedb.InsertServiceParams{ID: id, TeamID: text(p.Scope.TeamID), Name: s.Name, NameScope: "allocation/" + id, CreatedByIdentityID: text(p.CreatorID), IdempotencyKey: "allocation/" + id, RequestDigest: ownership[:], Now: timestamptz(clock.entered)}); err != nil {
		return ServiceRecord{}, err
	}
	trust, err := appliedServiceTargetTrust(s.TargetTLS)
	if err != nil {
		return ServiceRecord{}, err
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		return ServiceRecord{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.services SET protocol='http',tls_metadata=$2::jsonb,ephemeral=true,
		expires_at=$3,require_post_quantum=COALESCE($4,false) WHERE id=$1`, id, string(encoded), until, s.RequirePostQuantum); err != nil {
		return ServiceRecord{}, err
	}
	if err = d.saveServiceConfiguration(ctx, tx, id, s); err != nil {
		return ServiceRecord{}, err
	}
	if err = q.InsertPublisherAllocation(ctx, controlstatedb.InsertPublisherAllocationParams{ServiceID: id, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, InvocationID: r.Invocation, DeploymentID: nullableText(deployment), RequiredTemporaryApproval: mode, RequestedExpiresAt: nullableTime(requestedExpiry)}); err != nil {
		return ServiceRecord{}, err
	}
	if err = allocateServiceEndpoint(ctx, tx, id, deployment, domain, namespace, clock.current()); err != nil {
		return ServiceRecord{}, err
	}
	if err = auditPrivateMutation(ctx, tx, id, p.CreatorID, "service.create", id, clock.current()); err != nil {
		return ServiceRecord{}, err
	}
	row, err := q.LockService(ctx, id)
	if err != nil {
		return ServiceRecord{}, err
	}
	return d.publisherServiceRecord(ctx, tx, row)
}

func sameAllocationDeadline(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

// PostgreSQL stores microseconds. floor before capture and retry comparison so
// an exact caller retry is portable without ever extending its fixed deadline.
func allocationDeadline(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	canonical := value.UTC().Truncate(time.Microsecond)
	return &canonical
}

// publisher deletion uses allocation ownership and current publication permission,
// never human management authority or a hostname/deployment-name lookup.
func (d *Database) DeletePublisherService(ctx context.Context, p PublisherIdentity, id string, now time.Time) (retErr error) {
	if !opaqueid.Valid(id, opaqueid.ServicePrefix) || p.Scope.Kind != "namespace" && p.Scope.Kind != DeploymentCredentialGrant {
		return ErrServiceAccess
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete allocated service", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, p.Scope.TeamID); err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	allocation, err := q.GetPublisherAllocation(ctx, id)
	if err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	if allocation.PublisherIdentityID != p.ID || allocation.PublisherGrantID != p.GrantID {
		return ErrServiceAccess
	}
	service, err := q.LockService(ctx, id)
	if err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	if _, err = d.currentServiceAllocator(ctx, q, p, clock.current(), true); err != nil {
		return err
	}
	if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, id, clock.current()); err != nil {
		return err
	}
	if err = d.retireProjectResource(ctx, tx, q, controlstatedb.ControlAppliedProjectService{ServiceID: text(id), TeamID: p.Scope.TeamID}, clock.current()); err != nil {
		return err
	}
	if err = auditPrivateMutation(ctx, tx, id, p.CreatorID, "service.delete", id, clock.current()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return err
	}
	if _, err = d.currentServiceAllocator(ctx, q, p, clock.current(), false); err != nil {
		return err
	}
	if service.ExpiresAt.Valid && !service.ExpiresAt.Time.After(clock.current()) {
		return ErrServiceAccess
	}
	return tx.Commit(ctx)
}
