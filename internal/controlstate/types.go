package controlstate

// PublicURLScope identifies whether a public URL belongs to one membership or a team.
type PublicURLScope string

const (
	PublicURLScopeMember PublicURLScope = "member"
	PublicURLScopeShared PublicURLScope = "shared"
)

// PublicURLLifecycleState is the stored state of a public URL.
type PublicURLLifecycleState string

const (
	PublicURLLifecycleEnabled   PublicURLLifecycleState = "enabled"
	PublicURLLifecycleSuspended PublicURLLifecycleState = "suspended"
	PublicURLLifecycleDeleted   PublicURLLifecycleState = "deleted"
)

// PublicURLDNSState is the stored state of public URL DNS.
type PublicURLDNSState string

const (
	PublicURLDNSUnmanaged PublicURLDNSState = "unmanaged"
	PublicURLDNSPending   PublicURLDNSState = "pending"
	PublicURLDNSPublished PublicURLDNSState = "published"
	PublicURLDNSRemoving  PublicURLDNSState = "removing"
	PublicURLDNSRemoved   PublicURLDNSState = "removed"
	PublicURLDNSFailed    PublicURLDNSState = "failed"
)

// PublishRunState is the stored state of one publish run.
type PublishRunState string

const (
	PublishRunStarting PublishRunState = "starting"
	PublishRunReady    PublishRunState = "ready"
	PublishRunClosed   PublishRunState = "closed"
	PublishRunExpired  PublishRunState = "expired"
	PublishRunCanceled PublishRunState = "canceled"
)

// PublisherConnectionState is the stored state of one connection slot.
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
	IngressPublicURLUpsert    IngressRoutingTableEventKind = "public_url_upsert"
	IngressPublicURLTombstone IngressRoutingTableEventKind = "public_url_tombstone"
	IngressChallengeUpsert    IngressRoutingTableEventKind = "challenge_upsert"
	IngressChallengeTombstone IngressRoutingTableEventKind = "challenge_tombstone"
)
