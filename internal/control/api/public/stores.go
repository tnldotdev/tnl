package public

import (
	"context"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Stores declares each API capability explicitly. nil optional stores retain
// their existing unavailable responses; methods on another store never enable them.
type Stores struct {
	PublicURLs                PublicURLStore
	Certificates              CertificateStore
	Admin                     AdminStore
	Visitors                  VisitorStore
	Previews                  PreviewStore
	PreviewTeamAccess         PreviewTeamAccessStore
	BrowserAccess             BrowserAccessStore
	Shares                    ShareStore
	ShareAccess               ShareAccessStore
	Feedback                  FeedbackStore
	Guests                    GuestStore
	GuestAuthorization        guestAuthorizationStore
	GuestPublishers           GuestPublisherStore
	PublisherRuns             PublisherRunStore
	PublisherIdentities       PublisherIdentityStore
	Applications              ApplicationRegistrationStore
	PublisherGroups           GroupStore
	PublisherRuntime          PublisherRuntimeStore
	ProjectConfiguration      ProjectConfigurationStore
	ProjectServices           ProjectServiceStore
	LocalProjects             LocalProjectStore
	Services                  ServiceStore
	ServiceRuns               ServiceRunStore
	ServiceCertificates       managedCertificateStore
	ServiceClientCertificates ServiceClientCertificateStore
	ServiceHTTP               ServiceHTTPStore
	ServiceAudit              ServiceAuditStore
	ConnectorPeerPairs        ConnectorPeerPairStore
	VisitorPolicy             publisherVisitorPolicyStore
	VisitorTokens             visitorTokenIssuer
	CompanyBrowser            CompanyBrowserStore
	BrowserSessions           BrowserSessionStore
	Workloads                 WorkloadVisitorStore
}

type GuestStore interface {
	CreateGuestTrial(context.Context, controlstate.NewGuestTrial, string, time.Time) (string, error)
	GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error)
	GuestOwnsPublicURL(context.Context, string, string) (bool, error)
	GuestSourceMatches(controlstate.GuestTrial, string) (bool, error)
	AllocateGuestDemoNumber(context.Context, string, time.Time) (int64, error)
	GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error
}

type GroupStore interface {
	PublisherGroupStore
	RenamePublisherNamespace(context.Context, controlstate.RenamePublisherNamespaceRequest) (controlstate.AppliedProjectConfiguration, error)
	RenamePublisherGroup(context.Context, string, string, string, string, string, int64, time.Time) (controlstate.AppliedProjectConfiguration, error)
}

type PublisherRuntimeStore interface {
	PublisherRuntime(context.Context, controlstate.PublisherRuntimeRequest) (controlstate.PublisherRuntimeResponse, error)
}

type ProjectServiceStore interface {
	GetProjectService(context.Context, controlstate.GetProjectServiceRequest) (controlstate.ServiceRecord, error)
}

type LocalProjectStore interface {
	GetLocalProjectService(context.Context, controlstate.GetLocalProjectServiceRequest) (controlstate.LocalProjectService, error)
	RealizeLocalProjectService(context.Context, controlstate.RealizeLocalProjectServiceRequest) (controlstate.LocalProjectService, error)
	GetProjectPublicMetadata(context.Context, string, string, string, time.Time) (controlstate.ProjectPublicMetadata, error)
}

type ServiceStore interface {
	serviceVisitorStore
	GetServiceForPublisher(context.Context, string, controlstate.PublisherIdentity, time.Time) (controlstate.ServiceRecord, error)
}

type ServiceRunStore interface {
	serviceRunStore
	StartServiceRun(context.Context, string, string, int64, controlstate.PublisherIdentity, time.Time) (controlstate.ServiceRunState, error)
}

type ServiceClientCertificateStore interface {
	IssueServiceClientCertificate(context.Context, string, string, string, []byte, time.Time) (controlstate.ServiceClientCertificate, error)
	AuthorizeServiceClientCertificate(context.Context, string, string, string, string, int64, netip.Addr, []byte, time.Time) (controlstate.ServiceVisitorValidity, error)
}

type ServiceHTTPStore interface {
	serviceHTTPStore
	ListServiceHTTPGrants(context.Context, string, string, time.Time) ([]controlv1.ServiceHTTPGrantSummary, error)
	RefreshServiceBrowserSession(context.Context, string, string, time.Time, func(context.Context, string) (controlstate.BrowserTokenRotation, error)) (controlstate.BrowserAccessSession, error)
}

type ServiceAuditStore interface {
	serviceAuditStore
	IngestServiceRunObservations(context.Context, string, string, string, int64, serviceaudit.Batch, time.Time) (controlstate.ServiceObservationResult, error)
}

type ConnectorPeerPairStore interface {
	connectorPeerPairStore
	RebindConnectorPeerPair(context.Context, string, string, controlstate.ConnectorPeerPairRebindRequest, time.Time) (controlstate.ConnectorPeerPairRebindState, error)
	ListConnectorPeerPairs(context.Context, string, string, string, string, time.Time) (controlstate.ConnectorPeerPairCandidates, error)
	ConfirmConnectorPeerPairPrepared(context.Context, string, string, string, string, controlstate.ConnectorPeerPairPrepared, time.Time) error
	DeliverConnectorPeerPair(context.Context, string, string, string, int64, string, time.Time) (controlstate.ConnectorPeerPairDelivery, error)
}

type CompanyBrowserStore interface {
	PrepareCompanyBrowser(context.Context, string, string, string, string, time.Time) (*controlstate.CompanyLoginIntent, error)
}

type BrowserSessionStore interface {
	CreateOIDCControlSession(context.Context, string, controlstate.OIDCIdentity, time.Duration, time.Duration, time.Time) (controlstate.ControlSession, error)
}

// DatabaseStores binds the built-in database at compile time, without runtime
// capability discovery. daemon composition and real database fixtures share it.
func DatabaseStores(database *controlstate.Database) Stores {
	if database == nil {
		return Stores{}
	}
	return Stores{
		PublicURLs: database, Certificates: database, Admin: database,
		Visitors: database, Previews: database, PreviewTeamAccess: database,
		BrowserAccess: database, Shares: database, ShareAccess: database, Feedback: database,
		Guests: database, GuestAuthorization: database, GuestPublishers: database,
		PublisherRuns: database, PublisherIdentities: database, PublisherGroups: database, Applications: database,
		PublisherRuntime: database, ProjectConfiguration: database, ProjectServices: database,
		LocalProjects: database, Services: database, ServiceRuns: database,
		ServiceCertificates: database, ServiceClientCertificates: database, ServiceHTTP: database,
		ServiceAudit: database, ConnectorPeerPairs: database, VisitorPolicy: database,
		VisitorTokens: database, CompanyBrowser: database, BrowserSessions: database, Workloads: database,
	}
}
