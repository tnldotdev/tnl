package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

type AllocateGuestDemoServiceRequest struct {
	Credential         GuestCredential
	IdempotencyKey     string
	Target             string
	RequirePostQuantum bool
	DNSAutomation      bool
	Now                time.Time
}

// normalize only the bound demo listener. neither hostname nor visitor policy
// comes from the caller; the saved declaration is supplied by control.
func guestDemoTarget(target string) (string, error) {
	if len(target) == 0 || len(target) > 256 {
		return "", ErrProjectConfigurationInvalid
	}
	u, err := parseAppliedHTTPOrigin(target)
	if err != nil || u.Scheme != "http" || u.Port() == "" {
		return "", ErrProjectConfigurationInvalid
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Unmap().IsLoopback() || ip.Zone() != "" {
		return "", ErrProjectConfigurationInvalid
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", ErrProjectConfigurationInvalid
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)), nil
}

func guestDemoDeclaration(target, hostname, domain string, postQuantum bool) (*ProjectServiceConfiguration, error) {
	return normalizeServiceConfiguration("demo", &ProjectServiceConfiguration{
		Name: "demo", Protocol: "http", Target: target, Hostname: hostname, DomainID: domain,
		Ephemeral: true, RequirePostQuantum: &postQuantum, Public: new(true),
		HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted"}},
		// cumulative totals remain unlimited, independently of instantaneous
		// connection and byte rates and the trial's READY-time allowance.
		Traffic: &trafficlimits.Selection{TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(0)), TotalDownloadBytes: new(int64(0))},
	})
}

func (d *Database) AllocateGuestDemoService(ctx context.Context, request AllocateGuestDemoServiceRequest) (result ServiceRecord, retErr error) {
	clock := newAuthorizationClock(request.Now)
	if request.Now.IsZero() || len(request.IdempotencyKey) == 0 || len(request.IdempotencyKey) > 128 {
		return result, ErrServiceAccess
	}
	target, err := guestDemoTarget(request.Target)
	if err != nil {
		return result, err
	}
	intent, err := json.Marshal(struct {
		Target             string
		RequirePostQuantum bool
	}{target, request.RequirePostQuantum})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(intent)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "allocate guest demo service", &retErr)()
	q := controlstatedb.New(tx)
	trial, err := d.lockGuestCredential(ctx, q, request.Credential, clock)
	if err != nil {
		return result, err
	}
	// recover before checking the READY budget or outstanding authority: a lost
	// response must still let the owner find and delete its original allocation.
	previous, err := q.FindGuestServiceAllocation(ctx, controlstatedb.FindGuestServiceAllocationParams{
		GuestID: text(trial.ID), IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		previous, err = q.LockService(ctx, previous.ID)
		if err != nil {
			return result, err
		}
		if previous.GuestID.String != trial.ID || previous.TeamID.Valid || !previous.Enabled || previous.DeletedAt.Valid ||
			!previous.ExpiresAt.Time.After(clock.current()) || !bytes.Equal(previous.RequestDigest, digest[:]) {
			return result, ErrServiceConflict
		}
		result, err = checkedServiceRecord(previous)
		if err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			return ServiceRecord{}, err
		}
		if !trial.ExpiresAt.Time.After(clock.current()) {
			return ServiceRecord{}, ErrGuestTrialSpent
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if !guestPublicationEligible(trial, clock.current()) {
		return result, ErrGuestTrialSpent
	}
	count, err := q.CountGuestCurrentServices(ctx, text(trial.ID))
	if err != nil {
		return result, err
	}
	if count != 0 || trial.ActiveServiceRunID.Valid || trial.ServingUntil.Valid && trial.ServingUntil.Time.After(clock.current()) {
		return result, ErrServiceConflict
	}
	var domain string
	err = tx.QueryRow(ctx, `SELECT canonical_domain
		FROM control.domains WHERE id=$1 AND kind='managed' AND state='ready' AND released_at IS NULL
		FOR SHARE`, trial.DomainID).Scan(&domain)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	var pool string
	err = tx.QueryRow(ctx, `SELECT id FROM control.ingress_pools WHERE id=$1 AND state='enabled' FOR SHARE`, trial.IngressPoolID).Scan(&pool)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err := requireNewServiceWork(ctx, q, MaintenanceControlServiceCreation); err != nil {
		return result, err
	}
	number, err := q.AdvanceGuestDemoNumber(ctx, controlstatedb.AdvanceGuestDemoNumberParams{
		ID: trial.ID, AllocatedAt: timestamptz(clock.current()),
	})
	if err != nil {
		return result, publisherLookupError(err, ErrGuestTrialSpent)
	}
	hostname := "demo-" + strconv.FormatInt(number, 10) + "." + trial.NamespaceLabel + "." + domain
	declaration, err := guestDemoDeclaration(target, hostname, trial.DomainID, request.RequirePostQuantum)
	if err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return result, err
	}
	// guest constraints require the complete approved endpoint at insertion.
	// the record, declaration, and ordinary endpoint commit as one allocation.
	_, err = tx.Exec(ctx, `INSERT INTO control.services(id,guest_id,name,name_scope,protocol,ephemeral,public,
		service_port,domain_id,ingress_pool_id,certificate_hostname,certificate_scope,expires_at,
		require_post_quantum,idempotency_key,request_digest,created_at,updated_at)
		VALUES($1,$2,'demo',$2,'http',true,true,443,$3,$4,$5,$5,$6,$7,$8,$9,$10,$10)`,
		id, trial.ID, trial.DomainID, pool, hostname, trial.ExpiresAt.Time, request.RequirePostQuantum,
		request.IdempotencyKey, digest[:], request.Now)
	if err != nil {
		return result, projectConstraintError(err)
	}
	if err = d.saveServiceConfiguration(ctx, tx, id, *declaration); err != nil {
		return result, err
	}
	if err = reconcileServiceEndpoint(ctx, tx, serviceEndpoint{
		ServiceID: id, DomainID: trial.DomainID, Hostname: hostname, Namespace: hostname, PoolID: pool,
		Public: true, Automation: request.DNSAutomation,
	}, clock.current()); err != nil {
		return result, err
	}
	row, err := q.LockService(ctx, id)
	if err != nil {
		return result, err
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ServiceRecord{}, err
	}
	if !guestPublicationEligible(trial, clock.current()) {
		return ServiceRecord{}, ErrGuestTrialSpent
	}
	return result, tx.Commit(ctx)
}
