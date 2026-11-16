package state

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// IngressServiceRun contains the facts ingress needs before a visitor arrives.
// source authority proves the original socket addresses, not visitor permission.
type IngressServiceRun struct {
	ServiceID, RunID, Protocol, Hostname string
	RunNumber, EndpointRevision          int64
	Port                                 int
	ValidUntil                           time.Time
	Anonymous                            bool
	IP                                   *controlv1.VisitorPolicyIP
	Traffic                              trafficlimits.Limits
	Relays                               []ServiceRelay
	SourceAuthority                      []byte
	SourceKey                            []byte
	RecoveryEpisodeID                    *int64
}

type IngressServices struct {
	ObservedAt time.Time
	ValidUntil time.Time
	Runs       []IngressServiceRun
}

// ReadIngressServices reads current serving facts without locking publication
// rows or writing visitor records. ingress replaces its local view as one unit.
func (d *Database) ReadIngressServices(ctx context.Context, identity IngressLeaseIdentity, now time.Time) (result IngressServices, retErr error) {
	if validateIngressLeaseIdentity(identity) != nil {
		return result, ErrIngressLeaseStale
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read ingress services", &retErr)()
	q := controlstatedb.New(tx)
	lease, err := q.GetIngressServingLease(ctx, controlstatedb.GetIngressServingLeaseParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: int64(identity.IngressLeaseRevision), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && lease.Draining {
		return result, ErrIngressLeaseStale
	}
	if err != nil {
		return result, err
	}
	rows, err := q.ListIngressServiceRuns(ctx, controlstatedb.ListIngressServiceRunsParams{
		IngressPoolID: lease.IngressPoolID, Now: timestamptz(now),
	})
	if err != nil {
		return result, err
	}
	result.ObservedAt = now
	result.ValidUntil = minTime(now.Add(d.servingTolerance()), lease.ServingUntil.Time)
	result.Runs = make([]IngressServiceRun, 0, len(rows))
	ids := make([]string, 0, len(rows))
	serviceIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ControlServiceRun.ID)
		if len(serviceIDs) == 0 || serviceIDs[len(serviceIDs)-1] != row.ControlService.ID {
			serviceIDs = append(serviceIDs, row.ControlService.ID)
		}
	}
	configurations, err := d.serviceConfigurations(ctx, q, serviceIDs)
	if err != nil {
		return result, err
	}
	connections, err := q.ListIngressServiceRelays(ctx, controlstatedb.ListIngressServiceRelaysParams{
		ServiceRunIds: ids, Now: timestamptz(now),
	})
	if err != nil {
		return result, err
	}
	relays := make(map[string][]ServiceRelay, len(rows))
	for _, slot := range connections {
		relays[slot.ServiceRunID] = append(relays[slot.ServiceRunID], ServiceRelay{
			PublisherConnectionID: slot.PublisherConnectionID, ConnectionSlot: slot.ConnectionSlot,
			ConnectionAssignmentRevision: slot.ConnectionAssignmentRevision, RelayServiceID: slot.RelayServiceID,
			RelayID: slot.RelayID, RelayRunID: slot.RelayRunID, RelayLeaseRevision: slot.RelayLeaseRevision,
			InternalRelayAddress: slot.InternalRelayAddress, TLSServerName: slot.TlsServerName,
			LeaseExpiresAt: slot.LeaseExpiresAt.Time, ServingUntil: slot.ServingUntil.Time,
		})
	}
	for _, row := range rows {
		service, run := row.ControlService, row.ControlServiceRun
		if service.Protocol == "http" && !lease.Https ||
			service.Protocol != "http" && !slices.Contains(lease.ServicePorts, service.ServicePort.Int32) {
			continue
		}
		connected := relays[run.ID]
		if len(connected) == 0 {
			continue
		}
		until := minTime(result.ValidUntil, row.ValidUntil.Time)
		if service.ExpiresAt.Valid {
			until = minTime(until, service.ExpiresAt.Time)
		}
		// source proofs use whole seconds. omit a run with no usable deadline
		// instead of failing every other service's refresh.
		if until.Unix() <= now.Unix() {
			continue
		}
		entry := IngressServiceRun{ServiceID: service.ID, RunID: run.ID, RunNumber: run.RunNumber,
			Protocol: service.Protocol, Hostname: service.CertificateHostname, Port: int(service.ServicePort.Int32),
			EndpointRevision: service.EndpointRevision, ValidUntil: until, Relays: connected}
		if row.RecoveryEpisodeID.Valid {
			entry.RecoveryEpisodeID = &row.RecoveryEpisodeID.Int64
		}
		entry.Traffic, err = decodeRunTraffic(run.TrafficLimits)
		if err != nil {
			return result, err
		}
		var settings *config.HTTPService
		declaration, found := configurations[service.ID]
		if !found {
			return result, ErrServiceAccess
		}
		if declaration != nil {
			settings = declaration.HTTP
		}
		if settings != nil && settings.Access != nil {
			entry.Anonymous = service.Protocol == "http" && settings.Access.VisitorMode() == "anonymous"
			if len(settings.Access.IP) != 0 {
				key, err := d.storageKey.IPPolicyKey(d.storageKey.CurrentID(), "visitor-policy:service:"+service.ID)
				if err != nil {
					return result, err
				}
				entry.IP = &controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{}}
				for _, raw := range settings.Access.IP {
					prefix, err := netip.ParsePrefix(raw)
					if err != nil {
						return result, err
					}
					hashed, err := ippolicy.Hash(key, prefix)
					if err != nil {
						return result, err
					}
					entry.IP.Prefixes = append(entry.IP.Prefixes, controlv1.HashedIPPrefix{
						Family: controlv1.HashedIPPrefixFamily(hashed.Family), PrefixLength: hashed.Bits, Digest: hashed.Digest,
					})
				}
			}
		}
		master, err := visitortoken.ServiceVisitorSourceKey(run.RunTokenDigest, run.ID, uint64(run.RunNumber))
		if err != nil {
			return result, err
		}
		authority, key, err := visitortoken.IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{
			ServiceID: service.ID, ServiceRunID: run.ID, RunNumber: uint64(run.RunNumber), EndpointRevision: service.EndpointRevision,
			IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
			IngressLeaseRevision: identity.IngressLeaseRevision, VisitorPolicyRevision: row.VisitorPolicyRevision,
			ValidUntil: until.Unix(),
		}, now)
		if err != nil {
			return result, err
		}
		entry.SourceAuthority, err = authority.MarshalBinary()
		if err != nil {
			return result, err
		}
		entry.SourceKey = key[:]
		result.Runs = append(result.Runs, entry)
	}
	return result, tx.Commit(ctx)
}
