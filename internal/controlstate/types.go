package controlstate

// RouteScope identifies whether a route belongs to one membership or a team.
type RouteScope string

const (
	RouteScopeMember RouteScope = "member"
	RouteScopeShared RouteScope = "shared"
)

// RouteLifecycleState is the durable lifecycle of a route.
type RouteLifecycleState string

const (
	RouteLifecycleEnabled   RouteLifecycleState = "enabled"
	RouteLifecycleSuspended RouteLifecycleState = "suspended"
	RouteLifecycleDeleted   RouteLifecycleState = "deleted"
)

// RouteDNSState is the durable public route DNS lifecycle.
type RouteDNSState string

const (
	RouteDNSUnmanaged RouteDNSState = "unmanaged"
	RouteDNSPending   RouteDNSState = "pending"
	RouteDNSPublished RouteDNSState = "published"
	RouteDNSRemoving  RouteDNSState = "removing"
	RouteDNSRemoved   RouteDNSState = "removed"
	RouteDNSFailed    RouteDNSState = "failed"
)

// RouteSessionState is the durable lifecycle of one route session.
type RouteSessionState string

const (
	RouteSessionStarting RouteSessionState = "starting"
	RouteSessionReady    RouteSessionState = "ready"
	RouteSessionClosed   RouteSessionState = "closed"
	RouteSessionExpired  RouteSessionState = "expired"
	RouteSessionCanceled RouteSessionState = "canceled"
)

// PublisherConnectionState is the durable lifecycle of one connection slot.
type PublisherConnectionState string

const (
	PublisherConnectionAssigned  PublisherConnectionState = "assigned"
	PublisherConnectionConnected PublisherConnectionState = "connected"
	PublisherConnectionReady     PublisherConnectionState = "ready"
	PublisherConnectionDraining  PublisherConnectionState = "draining"
	PublisherConnectionClosed    PublisherConnectionState = "closed"
	PublisherConnectionExpired   PublisherConnectionState = "expired"
)

// IngressRoutingTableEventKind identifies one routing-table projection mutation.
type IngressRoutingTableEventKind string

const (
	IngressRouteUpsert        IngressRoutingTableEventKind = "route_upsert"
	IngressRouteTombstone     IngressRoutingTableEventKind = "route_tombstone"
	IngressChallengeUpsert    IngressRoutingTableEventKind = "challenge_upsert"
	IngressChallengeTombstone IngressRoutingTableEventKind = "challenge_tombstone"
)
