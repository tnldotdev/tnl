package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

// these are distinct publisher credentials, never alternate spellings for one
// token. operation entrypoints select one family before the shared transaction.
type connectorPeerPublisherSource struct {
	serviceID, runID, token string
	publishRun              *PublishRunAuthentication
}

func (connectorPeerPublisherSource) String() string   { return "connector peer publisher source" }
func (connectorPeerPublisherSource) GoString() string { return "connector peer publisher source" }

func (d *Database) connectorPeerPublisherPublication(ctx context.Context, tx pgx.Tx, source connectorPeerPublisherSource, now time.Time) (connectorPeerPublication, error) {
	q := controlstatedb.New(tx)
	if source.publishRun != nil {
		if source.serviceID != "" || source.runID != "" || source.token != "" {
			return connectorPeerPublication{}, ErrServiceAccess
		}
		auth := *source.publishRun
		if _, err := lockVisitorResource(ctx, tx, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}, now); err != nil {
			return connectorPeerPublication{}, err
		}
		_, run, err := lockAuthenticatedPublishRun(ctx, q, auth, now)
		if err != nil {
			return connectorPeerPublication{}, err
		}
		return d.connectorPairPublication(ctx, tx, ConnectorPeerPairRequest{PublicURLID: auth.PublicURLID,
			PublishRunID: run.ID, PublishRunNumber: run.PublishRunNumber, PublisherIdentityID: run.PublisherIdentityID.String, Action: "renew"}, now)
	}
	if err := lockServiceAdmission(ctx, tx, source.serviceID); err != nil {
		return connectorPeerPublication{}, err
	}
	run, err := serviceRunAuthorization(ctx, tx, q, source.serviceID, source.runID, source.token, now)
	if err != nil {
		return connectorPeerPublication{}, err
	}
	if _, err := lockVisitorResource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: source.serviceID}, now); err != nil {
		return connectorPeerPublication{}, err
	}
	return d.connectorPairPublication(ctx, tx, ConnectorPeerPairRequest{ServiceID: run.ServiceID, ServiceRunID: run.ID,
		RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID, Action: "renew"}, now)
}
