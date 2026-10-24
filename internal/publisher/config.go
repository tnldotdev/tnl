package publisher

import (
	"context"
	"errors"
	"net/http"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const defaultProvisioningStalledDelay = 2 * time.Minute

type PublicURLControlClient interface {
	GetPublicURLByHostname(context.Context, string, string) (controlv1.PublicURL, error)
	DeletePublicURL(context.Context, string) error
	CreatePublishRun(context.Context, string, string) (controlv1.PublishRunSetup, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken) error
	MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error
	HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.PublishRunToken, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error)
	MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.PublishRunToken) error
}

type PublicURLManagementClient interface {
	CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error)
	UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error)
}

type Config struct {
	PublisherIdentityID          string
	PreferredRegions             []string
	Control                      PublicURLControlClient
	VisitorControl               *clientcontrol.Client
	ControlURL                   string
	BrowserLoginAvailable        bool
	TeamID                       string
	DomainID                     string
	MembershipID                 string
	PolicyRevision               uint64
	PublicURLScope               controlv1.PublicURLScope
	Purpose                      controlv1.PublicURLPurpose
	Hostname                     string
	PreviewID                    string
	Feedback                     bool
	Demo                         bool
	ProjectRoot                  string
	Service                      string
	Target                       string
	ResolveTarget                func(context.Context) (string, string, error)
	ServiceProtocol              controlv1.PublicURLServiceProtocol
	AccessMode                   controlv1.VisitorAccessMode
	TargetTLSName                string
	PreserveSavedPublicURLTarget bool
	TargetOptions                publisherproxy.TargetOptions
	Handler                      http.Handler // integration URL handler; no local target is dialed.
	AdmitRequest                 func(*http.Request, PublishRunIdentity) error
	ObserveResponse              ResponseObserver
	Mounts                       []publisherproxy.Mount
	Limits                       ApplicationLimits
	ObserveSummary               inspection.Observer
	PromoteVisitor               PromoteVisitor
	AdmitVisitor                 AdmitVisitor
	ReadinessProof               func(PublishRunIdentity) *ReadinessProof
	OnWarning                    func(string)
	InspectionMode               inspection.Mode
	AllowedIPPrefixes            []string
	Ephemeral                    bool
	AssignedPublicURL            *controlv1.PublicURL
	State                        *clientstate.Store
	QUICConnector                muxsession.Connector
	TCPConnector                 muxsession.Connector
	FallbackDelay                time.Duration
	DrainTime                    time.Duration
	ProvisioningStalledDelay     time.Duration
	Logf                         func(string, ...any)
	Observe                      func(Event) error
	heartbeatInterval            time.Duration
}

// PublishRunIdentity binds a response observer to the run that served it.
type PublishRunIdentity struct {
	Hostname     string
	PublicURLID  string
	PublishRunID string
	Number       uint64
}

type ResponseObserver func(*http.Response, PublishRunIdentity) error

// configuredPublisherIdentityID binds local locks and certificate material to the
// enrolled identity. an explicit caller ID cannot override its signed adapter.
func configuredPublisherIdentityID(config Config) (string, error) {
	id := config.PublisherIdentityID
	if source, ok := config.Control.(interface{ PublisherIdentityID() string }); ok {
		selected := source.PublisherIdentityID()
		if id != "" && id != selected {
			return "", errors.New("public publisher identity differs from the selected grant")
		}
		id = selected
	}
	if !opaqueid.Valid(id, opaqueid.PublisherIdentityPrefix) {
		return "", errors.New("public publisher requires an enrolled publisher identity")
	}
	return id, nil
}
