package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativePeerPairDelivery is a local publisher binding, not permission to open
// an application stream. its key must stay with the exact run that requested it.
type NativePeerPairDelivery struct {
	PairID, ServiceID, ServiceRunID, PublisherIdentityID string
	RunNumber, DeliveryGeneration                        int64
	Subject                                              VisitorSubject
	DeliveryID                                           [16]byte
	Key                                                  string
	SourceIP                                             netip.Addr
	Relays                                               [2]NativePeerPairRelay
	ObservedAt, ExpiresAt                                time.Time
}

func (NativePeerPairDelivery) String() string   { return "native peer pair delivery" }
func (NativePeerPairDelivery) GoString() string { return "native peer pair delivery" }

// DeliverNativePeerPair reads only the already claimed delivery. the run lock
// serializes assignment changes and pair replacement; no key is created here.
func (d *Database) DeliverNativePeerPair(ctx context.Context, serviceID, runID, pairID string, generation int64, token string, now time.Time) (result NativePeerPairDelivery, retErr error) {
	if generation < 1 || pairID == "" || now.IsZero() || d.storageKey == nil {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "deliver native peer pair", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, now)
	if err != nil {
		return result, err
	}
	if run.State != "ready" || !run.Healthy || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: serviceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if _, err = lockVisitorResource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: serviceID}, now); err != nil {
		return result, err
	}
	pair, err := q.LockNativePeerPairForLegClaim(ctx, pairID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if pair.ServiceID != serviceID || pair.ServiceRunID != runID || pair.RunNumber != run.RunNumber ||
		pair.PublisherIdentityID != run.PublisherIdentityID || pair.DeliveryGeneration != generation || !pair.ExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	result.Subject.Kind = pair.SubjectKind
	var parentUntil time.Time
	if pair.SubjectKind == tunnelv1.VisitorHumanDevice {
		result.Subject.DeviceID = pair.SubjectID
		if !pair.ParentControlSessionID.Valid {
			return NativePeerPairDelivery{}, ErrServiceAccess
		}
		if err = tx.QueryRow(ctx, `SELECT identity_id FROM control.visitor_devices WHERE id=$1 AND revoked_at IS NULL FOR SHARE`, pair.SubjectID).Scan(&result.Subject.IdentityID); err != nil {
			return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
		}
		if err = tx.QueryRow(ctx, `SELECT LEAST(access_expires_at,refresh_expires_at) FROM control.control_sessions
			WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL AND access_expires_at>$3 AND refresh_expires_at>$3 FOR SHARE`,
			pair.ParentControlSessionID.String, result.Subject.IdentityID, now).Scan(&parentUntil); err != nil {
			return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
		}
	} else if pair.SubjectKind == tunnelv1.VisitorWorkloadSession {
		result.Subject.WorkloadSessionID = pair.SubjectID
	} else {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	_, subjectUntil, err := AuthenticateVisitorSubjectKey(ctx, tx, result.Subject, serviceID, now)
	if err != nil || !subjectUntil.After(now) {
		return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
	}
	var bound [2]NativePeerPairRelay
	if json.Unmarshal(pair.Slots, &bound) != nil {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	slots, err := q.ListServiceConnectionSlots(ctx, runID)
	if err != nil {
		return result, err
	}
	if len(slots) != 2 || slots[0].RelayServiceID == slots[1].RelayServiceID {
		return result, ErrServiceAccess
	}
	for i, slot := range slots {
		leg := bound[i]
		lease := leg.RelayLease
		if int(slot.ConnectionSlot) != i || slot.ServiceID != serviceID || slot.RunNumber != run.RunNumber || slot.State != "ready" || !slot.SessionOpen ||
			slot.PublisherConnectionID != leg.PublisherConnectionID || slot.ConnectionAssignmentRevision != leg.AssignmentRevision ||
			slot.RelayServiceID != lease.RelayServiceID || !slot.RelayID.Valid || slot.RelayID.String != lease.RelayID ||
			!slot.RelayRunID.Valid || slot.RelayRunID.String != lease.RelayRunID || !slot.RelayLeaseRevision.Valid || slot.RelayLeaseRevision.Int64 != int64(lease.RelayLeaseRevision) ||
			slot.RelayAddress != leg.RelayAddress || slot.TlsServerName != leg.TLSServerName {
			return NativePeerPairDelivery{}, ErrServiceAccess
		}
		var source netip.Addr
		var relayID, relayRunID, address, serverName string
		var revision int64
		err = tx.QueryRow(ctx, `SELECT claim.source_ip,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,relay.relay_address,relay.tls_server_name
			FROM control.native_peer_pair_leg_claims claim
			JOIN control.relay_leases lease ON lease.relay_id=claim.relay_id AND lease.relay_run_id=claim.relay_run_id AND lease.relay_lease_revision=claim.relay_lease_revision
			JOIN control.relay_services relay ON relay.relay_service_id=lease.relay_service_id
			WHERE claim.pair_id=$1 AND claim.connection_slot=$2 AND lease.relay_service_id=$3 AND lease.lease_expires_at>$4
			AND NOT lease.draining AND relay.enabled FOR SHARE OF lease,relay`, pairID, i, lease.RelayServiceID, now).
			Scan(&source, &relayID, &relayRunID, &revision, &address, &serverName)
		if err != nil {
			return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
		}
		if relayID != lease.RelayID || relayRunID != lease.RelayRunID || revision != int64(lease.RelayLeaseRevision) ||
			address != leg.RelayAddress || serverName != leg.TLSServerName || !source.IsValid() || source.Zone() != "" || source != source.Unmap() ||
			i > 0 && source != result.SourceIP {
			return NativePeerPairDelivery{}, ErrServiceAccess
		}
		result.SourceIP = source
	}
	if err = d.serviceHTTPSourceAllowed(ctx, q, serviceID, result.SourceIP); err != nil {
		return NativePeerPairDelivery{}, err
	}
	// the pair's saved deadline is fixed; a later parent renewal cannot extend it.
	result.ExpiresAt = minTime(pair.ExpiresAt.Time, minTime(subjectUntil, minTime(run.PublisherExpiresAt.Time, run.CertificateExpiresAt.Time)))
	var grantUntil *time.Time
	if err = tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 AND kind='service' AND service_id=$3 AND revoked_at IS NULL`, run.PublisherGrantID, run.PublisherIdentityID, serviceID).Scan(&grantUntil); err != nil {
		return NativePeerPairDelivery{}, publisherLookupError(err, ErrServiceAccess)
	}
	if grantUntil != nil {
		result.ExpiresAt = minTime(result.ExpiresAt, *grantUntil)
	}
	if !parentUntil.IsZero() {
		result.ExpiresAt = minTime(result.ExpiresAt, parentUntil)
	}
	if !result.ExpiresAt.After(now) || len(pair.DeliveryID) != len(result.DeliveryID) {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	copy(result.DeliveryID[:], pair.DeliveryID)
	if result.DeliveryID == [16]byte{} {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	secret, _, err := d.storageKey.Open(pair.StorageKeyID, nativePeerPairKeyContext(pair.ID), pair.KeyCiphertext)
	if err != nil {
		return NativePeerPairDelivery{}, err
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	if !bytes.Equal(digest[:], pair.KeyDigest) {
		return NativePeerPairDelivery{}, ErrServiceAccess
	}
	result.PairID, result.ServiceID, result.ServiceRunID, result.PublisherIdentityID = pair.ID, serviceID, runID, run.PublisherIdentityID
	result.RunNumber, result.DeliveryGeneration, result.Relays = run.RunNumber, generation, bound
	result.ObservedAt = now
	result.Key = base64.RawURLEncoding.EncodeToString(secret)
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPairDelivery{}, err
	}
	return result, nil
}
