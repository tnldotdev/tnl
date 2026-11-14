package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

// connectorPeerPublication is a transaction-local projection of one checked
// publication. the existing pair owner engine consumes its run, endpoint and
// deadline facts without treating a public URL as a saved service.
type connectorPeerPublication struct {
	scope          visitorscope.Scope
	runID          string
	number         int64
	publisherID    string
	publisherUntil time.Time
	metadata       ServiceMetadata
}

func (p connectorPeerPublication) serviceRunID() string {
	if p.scope.Kind == visitorscope.Service {
		return p.runID
	}
	return ""
}

func (p connectorPeerPublication) publishRunID() string {
	if p.scope.Kind == visitorscope.PublicURL {
		return p.runID
	}
	return ""
}

func (p connectorPeerPublication) matches(row controlstatedb.ControlConnectorPeerPair) bool {
	if row.PublisherIdentityID != p.publisherID {
		return false
	}
	if p.scope.Kind == visitorscope.Service {
		return row.ServiceID == p.scope.ID && row.ServiceRunID == p.runID && row.RunNumber == p.number &&
			row.PublicURLID == "" && row.PublishRunID == "" && row.PublishRunNumber == 0
	}
	return row.PublicURLID == p.scope.ID && row.PublishRunID == p.runID && row.PublishRunNumber == p.number &&
		row.ServiceID == "" && row.ServiceRunID == "" && row.RunNumber == 0
}

// resource admission is already held by visitorAuthorityForSource. keep the
// real run lock through owner lookup, replacement, renewal and commit.
func (d *Database) connectorPairPublication(ctx context.Context, tx pgx.Tx, r ConnectorPeerPairRequest, now time.Time) (p connectorPeerPublication, err error) {
	q := controlstatedb.New(tx)
	if r.PublicURLID == "" {
		p.scope = visitorscope.Scope{Kind: visitorscope.Service, ID: r.ServiceID}
		run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: r.ServiceRunID, ServiceID: r.ServiceID})
		if err != nil {
			return p, publisherLookupError(err, ErrServiceAccess)
		}
		retained := r.Action == "renew" && run.State == "starting" && run.ReadyAt.Valid
		if run.RunNumber != r.RunNumber || run.PublisherIdentityID != r.PublisherIdentityID || (run.State != "ready" && !retained) || !run.Healthy ||
			run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
			return p, ErrServiceAccess
		}
		p.runID, p.number, p.publisherID = run.ID, run.RunNumber, run.PublisherIdentityID
		p.publisherUntil, err = connectorPeerPublisherAuthority(ctx, tx, run, now)
		if err != nil {
			return p, err
		}
		service, err := q.GetService(ctx, r.ServiceID)
		if err != nil {
			return p, err
		}
		p.metadata, err = checkedServiceMetadata(service)
		return p, err
	}
	p.scope = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: r.PublicURLID}
	url, err := q.LockPublicURLForRun(ctx, r.PublicURLID)
	if err != nil {
		return p, publisherLookupError(err, ErrServiceAccess)
	}
	run, err := q.LockPublishRun(ctx, r.PublishRunID)
	if err != nil {
		return p, publisherLookupError(err, ErrServiceAccess)
	}
	retained := r.Action == "renew" && run.State == "starting" && run.ReadyAt.Valid
	if run.PublicURLID != r.PublicURLID || run.PublishRunNumber != r.PublishRunNumber ||
		!run.PublisherIdentityID.Valid || run.PublisherIdentityID.String != r.PublisherIdentityID ||
		(run.State != "ready" && !retained) || run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) ||
		!run.CertificateInstalledAt.Valid || !run.CertificateNotAfter.Valid || !run.CertificateNotAfter.Time.After(now) ||
		!certificateidentity.Covers(run.CertificateIdentifiers, url.CanonicalHostname) {
		return p, ErrServiceAccess
	}
	p.runID, p.number, p.publisherID = run.ID, run.PublishRunNumber, run.PublisherIdentityID.String
	p.publisherUntil, err = d.connectorPublicURLPublisherAuthority(ctx, tx, url, run, now)
	if err != nil {
		return p, err
	}
	p.metadata = ServiceMetadata{Protocol: "http", PublisherPool: url.PublisherPool, TrustRevision: url.TrustRevision,
		Endpoint: managedServiceTLS(url.CanonicalHostname, int(url.Port), true)}
	if p.metadata.TrustRevision < 1 || p.metadata.Endpoint == nil {
		return p, ErrServiceMetadata
	}
	return p, nil
}

// these are checked slot facts, not a second wire model or assignment owner.
type connectorPeerConnection struct {
	slot                       int16
	resourceID                 string
	number                     int64
	connectionID, relayService string
	assignment                 int64
	state                      string
	open                       bool
	relayID, relayRunID        pgtype.Text
	leaseRevision              pgtype.Int8
	address, serverName        string
}

func (p connectorPeerPublication) connections(ctx context.Context, q *controlstatedb.Queries) ([]connectorPeerConnection, error) {
	var result []connectorPeerConnection
	if p.scope.Kind == visitorscope.Service {
		slots, err := q.ListServiceConnectionSlots(ctx, p.runID)
		if err != nil {
			return nil, err
		}
		for _, s := range slots {
			result = append(result, connectorPeerConnection{
				slot: s.ConnectionSlot, resourceID: s.ServiceID, number: s.RunNumber, connectionID: s.PublisherConnectionID,
				relayService: s.RelayServiceID, assignment: s.ConnectionAssignmentRevision, state: s.State, open: s.SessionOpen,
				relayID: s.RelayID, relayRunID: s.RelayRunID, leaseRevision: s.RelayLeaseRevision,
				address: s.RelayAddress, serverName: s.TlsServerName,
			})
		}
		return result, nil
	}
	slots, err := q.ListPublishRunConnections(ctx, p.runID)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		result = append(result, connectorPeerConnection{
			slot: s.ConnectionSlot, resourceID: s.PublicURLID, number: s.PublishRunNumber, connectionID: s.PublisherConnectionID,
			relayService: s.RelayServiceID, assignment: s.ConnectionAssignmentRevision, state: s.State, open: s.SessionOpen,
			relayID: s.ConnectedRelayID, relayRunID: s.ConnectedRelayRunID, leaseRevision: s.ConnectedRelayLeaseRevision,
			address: s.RelayAddress, serverName: s.TlsServerName,
		})
	}
	return result, nil
}

func (s connectorPeerConnection) ready(p connectorPeerPublication, slot int) bool {
	return int(s.slot) == slot && s.resourceID == p.scope.ID && s.number == p.number && s.state == "ready" && s.open &&
		opaqueid.Valid(s.connectionID, opaqueid.PublisherConnectionPrefix) && s.assignment >= 1 &&
		s.relayID.Valid && s.relayRunID.Valid && s.leaseRevision.Valid && s.leaseRevision.Int64 >= 1
}
