package state

// VisitorAccessMode selects whether tnl requires a visitor credential.
type VisitorAccessMode string

const (
	VisitorAccessRestricted VisitorAccessMode = "restricted"
	VisitorAccessAnonymous  VisitorAccessMode = "anonymous"
)

func (mode VisitorAccessMode) Valid() bool {
	return mode == VisitorAccessRestricted || mode == VisitorAccessAnonymous
}

// NamespaceScope identifies whether a publisher namespace belongs to one membership or a team.
type NamespaceScope string

const (
	NamespaceScopeMember NamespaceScope = "member"
	NamespaceScopeShared NamespaceScope = "shared"
)

// DNSAuthorityState is the stored state of a custom-domain DNS authority.
type DNSAuthorityState string

const (
	DNSAuthorityPending   DNSAuthorityState = "pending"
	DNSAuthorityReady     DNSAuthorityState = "ready"
	DNSAuthorityReleasing DNSAuthorityState = "releasing"
	DNSAuthorityReleased  DNSAuthorityState = "released"
	DNSAuthorityFailed    DNSAuthorityState = "failed"
)

func (state DNSAuthorityState) valid() bool {
	switch state {
	case DNSAuthorityPending, DNSAuthorityReady, DNSAuthorityReleasing, DNSAuthorityReleased, DNSAuthorityFailed:
		return true
	default:
		return false
	}
}

// ServiceEndpointDNSState is the stored state of a service endpoint's DNS.
type ServiceEndpointDNSState string

const (
	ServiceEndpointDNSUnmanaged ServiceEndpointDNSState = "unmanaged"
	ServiceEndpointDNSPending   ServiceEndpointDNSState = "pending"
	ServiceEndpointDNSPublished ServiceEndpointDNSState = "published"
	ServiceEndpointDNSRemoving  ServiceEndpointDNSState = "removing"
	ServiceEndpointDNSRemoved   ServiceEndpointDNSState = "removed"
	ServiceEndpointDNSFailed    ServiceEndpointDNSState = "failed"
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
