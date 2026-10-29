package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

// IngressRoutingTableProjection is the stored public URL view used by ingress.
type IngressRoutingTableProjection struct {
	PublishRunID         string                                   `json:"publish_run_id"`
	PublishRunClosed     bool                                     `json:"publish_run_closed,omitempty"`
	PublishRunReadyAt    *time.Time                               `json:"publish_run_ready_at,omitempty"`
	PublicURLID          string                                   `json:"public_url_id"`
	PublishRunNumber     uint64                                   `json:"publish_run_number"`
	CanonicalHostname    string                                   `json:"canonical_hostname"`
	IngressPoolID        string                                   `json:"ingress_pool_id,omitempty"`
	ServiceProtocol      PublicURLServiceProtocol                 `json:"service_protocol,omitempty"`
	Traffic              *trafficlimits.Limits                    `json:"traffic,omitempty"`
	PolicyRevision       uint64                                   `json:"policy_revision"`
	AccessMode           VisitorAccessMode                        `json:"access_mode"`
	IPPolicy             IPPolicy                                 `json:"ip_policy"`
	AllowedIPHashes      []ippolicy.Entry                         `json:"allowed_ip_hashes,omitempty"`
	IPPolicyKeyID        string                                   `json:"ip_policy_key_id,omitempty"`
	IPPolicyKey          [32]byte                                 `json:"-"`
	PublicUrlExpiresAt   time.Time                                `json:"public_url_expires_at"`
	RecoveryEpisodeID    *uint64                                  `json:"recovery_episode_id,omitempty"`
	PublisherConnections []IngressRoutingTablePublisherConnection `json:"publisher_connections"`
}

// IngressRoutingTablePublisherConnection identifies one connected relay that
// ingress may use for a visitor connection.
type IngressRoutingTablePublisherConnection struct {
	ConnectionSlot               int       `json:"connection_slot"`
	PublisherConnectionID        string    `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64    `json:"connection_assignment_revision"`
	RelayServiceID               string    `json:"relay_service_id"`
	RelayID                      string    `json:"relay_id"`
	RelayRunID                   string    `json:"relay_run_id"`
	RelayLeaseRevision           uint64    `json:"relay_lease_revision"`
	InternalRelayAddress         string    `json:"internal_relay_address"`
	TLSServerName                string    `json:"tls_server_name"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
	AvailableStreams             *int64    `json:"available_streams,omitempty"`
}

func validReadyPublisherConnections(
	ctx context.Context,
	queries *controlstatedb.Queries,
	publishRunID string,
	now time.Time,
) ([]controlstatedb.ListValidReadyPublisherConnectionsRow, error) {
	connections, err := queries.ListValidReadyPublisherConnections(
		ctx, controlstatedb.ListValidReadyPublisherConnectionsParams{
			PublishRunID: publishRunID, Now: timestamptz(now),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list ready publisher connections: %w", err)
	}
	return connections, nil
}

func (pending *pendingIngressRoutingTableEvents) addPublisherConnectionChanges(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
) error {
	published, err := publishRunRoutingPublished(ctx, queries, session)
	if err != nil {
		return err
	}
	if published {
		if _, err := pending.addRouteEvent(
			ctx, queries, route, session, connections,
			publicURLRoutingTableEventKind(len(connections) > 0), now,
		); err != nil {
			return err
		}
	}
	return nil
}

func publicURLRoutingTableEventKind(available bool) IngressRoutingTableEventKind {
	if available {
		return IngressPublicURLUpsert
	}
	return IngressPublicURLTombstone
}

func (pending *pendingIngressRoutingTableEvents) addRouteEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	return pending.addEvent(ctx, queries, route, session, connections, eventKind, session.PublisherExpiresAt.Time, now)
}

type publishedIngressRoutingTableEvent struct {
	routingTableRevision int64
	entryRevision        int64
}

type pendingIngressRoutingTableEvent struct {
	eventKind           IngressRoutingTableEventKind
	publicURLID         string
	publishRunNumber    int64
	canonicalHostname   string
	projection          []byte
	policyCiphertext    []byte
	policyStorageKeyID  string
	projectionExpiresAt time.Time
	createdAt           time.Time
	published           *publishedIngressRoutingTableEvent
}

type pendingIngressRoutingTableEvents struct {
	events []pendingIngressRoutingTableEvent
}

func (pending *pendingIngressRoutingTableEvents) addEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	projectionExpiresAt time.Time,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	policy := IPPolicy(route.IpPolicy)
	traffic, err := decodePublishRunTraffic(session.TrafficLimits)
	if err != nil {
		return nil, err
	}
	projection := IngressRoutingTableProjection{
		PublishRunClosed: session.ClosedAt.Valid,
		PublishRunID:     session.ID, PublicURLID: route.ID, PublishRunNumber: uint64(session.PublishRunNumber),
		CanonicalHostname: route.CanonicalHostname, PolicyRevision: uint64(route.PolicyRevision),
		IngressPoolID: route.IngressPoolID, ServiceProtocol: PublicURLServiceProtocol(route.ServiceProtocol),
		AccessMode:           VisitorAccessMode(route.AccessMode),
		IPPolicy:             policy,
		PublicUrlExpiresAt:   projectionExpiresAt,
		PublisherConnections: make([]IngressRoutingTablePublisherConnection, 0, len(connections)),
		Traffic:              &traffic,
	}
	if session.ReadyAt.Valid {
		readyAt := session.ReadyAt.Time
		projection.PublishRunReadyAt = &readyAt
	}
	var policyCiphertext []byte
	policyStorageKeyID := ""
	if eventKind == IngressPublicURLTombstone {
		projection.IPPolicy = IPPolicyAllowAll
	} else if policy == IPPolicyAllowlist {
		if len(route.AllowedIpHashes) == 0 || !route.AllowedIpHashKeyID.Valid {
			return nil, errors.New("controlstate: routing policy is not protected")
		}
		if err := json.Unmarshal(route.AllowedIpHashes, &projection.AllowedIPHashes); err != nil {
			return nil, errors.New("controlstate: stored hashed routing policy is invalid")
		}
		projection.IPPolicy = IPPolicyHashedAllowlist
		projection.IPPolicyKeyID = route.AllowedIpHashKeyID.String
		policyCiphertext = route.AllowedIpPolicyCiphertext
		policyStorageKeyID = route.AllowedIpPolicyStorageKeyID.String
	} else if policy != IPPolicyAllowAll || len(route.AllowedIpHashes) != 0 {
		return nil, errors.New("controlstate: routing policy is inconsistent")
	}
	if eventKind == "public_url_upsert" {
		episode, err := queries.GetOpenPublicURLRecoveryEpisode(ctx, controlstatedb.GetOpenPublicURLRecoveryEpisodeParams{
			PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
		})
		if err == nil {
			value := uint64(episode.ID)
			projection.RecoveryEpisodeID = &value
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("controlstate: read route recovery episode: %w", err)
		}
	}
	for _, connection := range connections {
		if !connection.ConnectedRelayID.Valid || !connection.ConnectedRelayRunID.Valid ||
			!connection.ConnectedRelayLeaseRevision.Valid || connection.ConnectedRelayLeaseRevision.Int64 <= 0 ||
			connection.ConnectionAssignmentRevision <= 0 || !connection.LeaseExpiresAt.Valid {
			return nil, errors.New("controlstate: invalid ingress routing-table publisher connection row")
		}
		projection.PublisherConnections = append(projection.PublisherConnections, IngressRoutingTablePublisherConnection{
			ConnectionSlot: int(connection.ConnectionSlot), PublisherConnectionID: connection.PublisherConnectionID,
			ConnectionAssignmentRevision: uint64(connection.ConnectionAssignmentRevision),
			RelayServiceID:               connection.RelayServiceID, RelayID: connection.ConnectedRelayID.String,
			RelayRunID:           connection.ConnectedRelayRunID.String,
			RelayLeaseRevision:   uint64(connection.ConnectedRelayLeaseRevision.Int64),
			InternalRelayAddress: connection.InternalRelayAddress, TLSServerName: connection.TlsServerName,
			LeaseExpiresAt:   connection.LeaseExpiresAt.Time,
			AvailableStreams: &connection.AvailableStreams,
		})
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return nil, fmt.Errorf("controlstate: encode ingress routing-table projection: %w", err)
	}
	published := &publishedIngressRoutingTableEvent{}
	pending.events = append(pending.events, pendingIngressRoutingTableEvent{
		eventKind: eventKind, publicURLID: route.ID, publishRunNumber: session.PublishRunNumber,
		canonicalHostname: route.CanonicalHostname, projection: payload,
		policyCiphertext: policyCiphertext, policyStorageKeyID: policyStorageKeyID,
		projectionExpiresAt: projectionExpiresAt, createdAt: now, published: published,
	})
	return published, nil
}

func (pending *pendingIngressRoutingTableEvents) publish(ctx context.Context, queries *controlstatedb.Queries) error {
	if len(pending.events) == 0 {
		return nil
	}
	// callers hold each public URL row through commit, so another transaction
	// cannot allocate an entry revision for that public URL concurrently.
	type publishRunNumber struct {
		publicURLID      string
		publishRunNumber int64
	}
	entryRevisionsByPublicURL := make(map[publishRunNumber]int64)
	entryRevisions := make([]int64, len(pending.events))
	for index := range pending.events {
		event := &pending.events[index]
		key := publishRunNumber{publicURLID: event.publicURLID, publishRunNumber: event.publishRunNumber}
		entryRevision, found := entryRevisionsByPublicURL[key]
		if !found {
			var err error
			entryRevision, err = queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
				PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
			})
			if err != nil {
				return fmt.Errorf("controlstate: read ingress routing-table entry revision: %w", err)
			}
		}
		if entryRevision == math.MaxInt64 {
			return errors.New("controlstate: ingress routing-table entry revision is exhausted")
		}
		entryRevision++
		entryRevisionsByPublicURL[key] = entryRevision
		entryRevisions[index] = entryRevision
	}
	// publish only after connection and challenge projections are complete.
	// hold the routing clock through commit so revision order matches commit order;
	// callers must not perform further database work. the final insert acquires
	// the clock itself when there is only one event.
	if len(pending.events) > 1 {
		if _, err := queries.LockIngressRoutingTableClock(ctx); err != nil {
			return fmt.Errorf("controlstate: lock ingress routing-table clock: %w", err)
		}
	}
	for index := range pending.events {
		event := &pending.events[index]
		publicURLExpiresAt := pgtype.Timestamptz{}
		if event.eventKind == IngressPublicURLUpsert {
			publicURLExpiresAt = timestamptz(event.projectionExpiresAt)
		}
		var routingTableRevision int64
		var err error
		if index == len(pending.events)-1 {
			routingTableRevision, err = queries.InsertFinalIngressRoutingTableEvent(ctx, controlstatedb.InsertFinalIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, PolicyCiphertext: event.policyCiphertext,
				PolicyStorageKeyID: nullableText(event.policyStorageKeyID),
				PublicUrlExpiresAt: publicURLExpiresAt, CreatedAt: timestamptz(event.createdAt),
				UpdatedAt: timestamptz(event.createdAt),
			})
		} else {
			routingTableRevision, err = queries.InsertIngressRoutingTableEvent(ctx, controlstatedb.InsertIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, PolicyCiphertext: event.policyCiphertext,
				PolicyStorageKeyID: nullableText(event.policyStorageKeyID),
				PublicUrlExpiresAt: publicURLExpiresAt, CreatedAt: timestamptz(event.createdAt),
			})
		}
		if err != nil {
			return fmt.Errorf("controlstate: insert ingress routing-table event: %w", err)
		}
		event.published.routingTableRevision = routingTableRevision
		event.published.entryRevision = entryRevisions[index]
	}
	return nil
}
