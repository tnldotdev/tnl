package stream

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// ConnectorHTTPAuthorization is one checked admission snapshot, not a credential
// supplied by HTTP. its token and permission change together after accepted renewal.
type ConnectorHTTPAuthorization struct {
	ServiceID, RunID   string
	RunNumber          uint64
	PairID             string
	DeliveryGeneration int64
	Source             netip.Addr
	PermissionToken    visitortoken.Token
	Permission         visitortoken.VerifiedPermission
	ValidUntil         time.Time
}

func (ConnectorHTTPAuthorization) String() string   { return "connector HTTP authorization" }
func (ConnectorHTTPAuthorization) GoString() string { return "connector HTTP authorization" }

// ConnectorHTTPProof is supplied explicitly by the actual stream admission.
// checking the socket or asserting an optional admission method is not proof.
type ConnectorHTTPProof interface {
	HTTPAuthorization(context.Context) (ConnectorHTTPAuthorization, error)
}

// ConnectorHTTPFrontend shares service-owned reserved handlers and application
// preparation without borrowing public forwarding headers or another HTTP engine.
type ConnectorHTTPFrontend interface {
	ConnectorReserved(http.ResponseWriter, *http.Request, ConnectorHTTPAuthorization) bool
	ConnectorApplication(http.ResponseWriter, *http.Request) *http.Request
}
