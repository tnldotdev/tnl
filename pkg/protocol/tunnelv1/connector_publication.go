package tunnelv1

import (
	"math"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

// exactly one publication family names a connector's authority. a saved public
// URL is never a service ID, even when both publications carry HTTP.
type connectorPublication struct {
	serviceID, serviceRunID   string
	runNumber                 uint64
	publicURLID, publishRunID string
	publishRunNumber          uint64
}

func (p connectorPublication) scope() visitorscope.Scope {
	if p.publicURLID != "" {
		return visitorscope.Scope{Kind: visitorscope.PublicURL, ID: p.publicURLID}
	}
	return visitorscope.Scope{Kind: visitorscope.Service, ID: p.serviceID}
}

func (p connectorPublication) valid() bool {
	if p.publicURLID != "" || p.publishRunID != "" || p.publishRunNumber != 0 {
		return p.serviceID == "" && p.serviceRunID == "" && p.runNumber == 0 &&
			opaqueid.Valid(p.publicURLID, opaqueid.PublicURLPrefix) &&
			opaqueid.Valid(p.publishRunID, opaqueid.PublishRunPrefix) &&
			p.publishRunNumber > 0 && p.publishRunNumber <= math.MaxInt64
	}
	return opaqueid.Valid(p.serviceID, opaqueid.ServicePrefix) &&
		opaqueid.Valid(p.serviceRunID, opaqueid.ServiceRunPrefix) &&
		p.runNumber > 0 && p.runNumber <= math.MaxInt64
}
