package publicapi_test

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/tnl"
)

// infer the otherwise unnameable token from one public method expression, then
// require every baseline method to accept that exact type. no internal package
// is imported, and the expected signatures are independent of today's adapter.
type runToken interface {
	~string
	String() string
}

type baselineNativeControl[Token runToken] interface {
	PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error)
	AllocatePublisherPublicURL(context.Context, string, controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error)
	DeletePublisherPublicURL(context.Context, string, string) error
	CreatePublisherRun(context.Context, string, string, string, string) (controlv1.PublishRunSetup, error)
	ClosePublishRun(context.Context, string, Token) error
	MarkPublishRunReady(context.Context, string, uint64, Token) error
	HeartbeatPublishRun(context.Context, string, uint64, Token) (controlv1.PublishRunHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, Token, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, Token) (controlv1.CertificateIssuance, error)
	MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, Token) error
	CreatePublishRunPreview(context.Context, string, uint64, Token) (controlv1.Preview, error)
	EnableShareAccess(context.Context, string, uint64, string, Token) error
	GetPublishRunShareState(context.Context, string, uint64, Token) (controlv1.PublishRunShareState, error)
	RedeemPublishRunShare(context.Context, string, controlv1.RedeemShareRequest, Token) (controlv1.ShareRedemption, error)
	RedeemBrowserHandoff(context.Context, string, uint64, string, Token) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, Token) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, Token) error
	AuthorizeHTTPVisitor(context.Context, string, controlv1.HTTPVisitorRequest, Token) (controlv1.HTTPVisitorResponse, error)
	CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, Token) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, Token) (controlv1.FeedbackThreadPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, Token) (controlv1.FeedbackEvent, error)
	GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, Token) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, Token) (controlv1.FeedbackEventPage, error)
}

type baselinePublisher[Token runToken] interface {
	baselineNativeControl[Token]
	Access(context.Context) (string, error)
	PublisherID() string
	ForGrant(controlv1.PublisherGrant) (*tnl.Publisher, error)
	SelectRoute(controlv1.PublicURL) error
	SavedURL(context.Context) (controlv1.PublicURL, error)
	Allocate(context.Context, controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error)
	GetPublicURLByHostname(context.Context, string, string) (controlv1.PublicURL, error)
	CreatePublishRun(context.Context, string, string) (controlv1.PublishRunSetup, error)
	CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error)
	UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error)
	DeletePublicURL(context.Context, string) error
	NamespaceScope() error
	Fork() (*tnl.Publisher, error)
	ControlURL() string
	PreparePrivateServiceRun(context.Context, string, string, string, ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, Token) (controlv1.PrivateServiceRunState, error)
	HeartbeatPrivateServiceRunHealth(context.Context, string, string, Token, controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, Token) error
	SavedPrivateService(context.Context) (controlv1.PrivateService, error)
	GetPublisherPrivateService(context.Context, string) (controlv1.PrivateService, error)
	CreatePrivateCertificateIssuance(context.Context, string, string, int64, Token, []byte, string) (controlv1.PrivateCertificateIssuance, error)
	GetPrivateCertificateIssuance(context.Context, string, string, string, Token) (controlv1.PrivateCertificateIssuance, error)
	MarkPrivateCertificateInstalled(context.Context, string, string, int64, string, time.Time, Token) error
	StartManagedServiceRun(context.Context, string, string, string, int64) (controlv1.PrivateServiceRunSetup, error)
	AuthorizeServiceClientCertificate(context.Context, string, string, Token, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error)
	AuthorizeServiceConnector(context.Context, string, string, Token, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error)
	AuthorizeManagedHTTPVisitor(context.Context, string, string, Token, controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error)
	RedeemManagedBrowserHandoff(context.Context, string, string, Token, controlv1.ManagedBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckManagedBrowserSession(context.Context, string, string, Token, controlv1.ManagedBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeManagedBrowserSession(context.Context, string, string, Token, controlv1.ManagedBrowserRequest) error
}

func requireNativeControl[Token runToken, Control baselineNativeControl[Token]](_ func(*tnl.Publisher, context.Context, string, Token) error, _ Control) struct{} {
	return struct{}{}
}

func requirePublisher[Token runToken, Publisher baselinePublisher[Token]](_ func(*tnl.Publisher, context.Context, string, Token) error, _ Publisher) struct{} {
	return struct{}{}
}

func requireTraffic[Selection any](_ func(*tnl.Publisher, *Selection) (*tnl.Publisher, error)) struct{} {
	return struct{}{}
}

type baselineRuntime interface {
	Renew(context.Context) (controlv1.PublisherRuntimeResponse, error)
	ObservabilityContext(context.Context, string, string) context.Context
	Stop(context.Context) error
	String() string
	GoString() string
}

func requireRuntime[Runtime baselineRuntime](_ func(*tnl.Publisher, string) (Runtime, error), _ func(*tnl.Publisher, Runtime)) struct{} {
	return struct{}{}
}

func requireAudit[Token runToken, Batch any](_ func(*tnl.Publisher, context.Context, string, Token) error, _ func(*tnl.Publisher, context.Context, string, uint64, Token, Batch) error) struct{} {
	return struct{}{}
}

var (
	_ = requireNativeControl((*tnl.Publisher).ClosePublishRun, (tnl.Publisher{}).NativeControl)
	_ = requireNativeControl((*tnl.Publisher).ClosePublishRun, (*tnl.Publisher)(nil))
	_ = requirePublisher((*tnl.Publisher).ClosePublishRun, (*tnl.Publisher)(nil))
	_ = requireTraffic((*tnl.Publisher).WithTraffic)
	_ = requireRuntime((*tnl.Publisher).RemoteRuntime, (*tnl.Publisher).WithRuntime)
	_ = requireAudit((*tnl.Publisher).ClosePublishRun, (*tnl.Publisher).ReportPublisherServiceObservations)
)

// method expressions, including promoted ones, remain usable as callbacks.
var _ = []any{
	(*tnl.Publisher).Access, (*tnl.Publisher).PublisherID, (*tnl.Publisher).ForGrant,
	(*tnl.Publisher).SelectRoute, (*tnl.Publisher).SavedURL, (*tnl.Publisher).Allocate,
	(*tnl.Publisher).GetPublicURLByHostname, (*tnl.Publisher).CreatePublishRun,
	(*tnl.Publisher).CreatePublicURL, (*tnl.Publisher).UpdatePublicURL, (*tnl.Publisher).DeletePublicURL,
	(*tnl.Publisher).NamespaceScope, (*tnl.Publisher).Fork, (*tnl.Publisher).ControlURL,
	(*tnl.Publisher).WithTraffic, (*tnl.Publisher).RemoteRuntime, (*tnl.Publisher).WithRuntime,
	(*tnl.Publisher).ReportPublisherServiceObservations,
	(*tnl.Publisher).PublisherPublicURL, (*tnl.Publisher).AllocatePublisherPublicURL,
	(*tnl.Publisher).DeletePublisherPublicURL, (*tnl.Publisher).CreatePublisherRun,
	(*tnl.Publisher).ClosePublishRun, (*tnl.Publisher).MarkPublishRunReady,
	(*tnl.Publisher).HeartbeatPublishRun, (*tnl.Publisher).CreateCertificateIssuance,
	(*tnl.Publisher).GetCertificateIssuance, (*tnl.Publisher).MarkPublishRunCertificateInstalled,
	(*tnl.Publisher).CreatePublishRunPreview, (*tnl.Publisher).EnableShareAccess,
	(*tnl.Publisher).GetPublishRunShareState, (*tnl.Publisher).RedeemPublishRunShare,
	(*tnl.Publisher).RedeemBrowserHandoff, (*tnl.Publisher).CheckBrowserAccess,
	(*tnl.Publisher).RevokeBrowserAccess, (*tnl.Publisher).AuthorizeHTTPVisitor,
	(*tnl.Publisher).CreateFeedbackReport, (*tnl.Publisher).ListPreviewPageFeedback,
	(*tnl.Publisher).AppendReviewerFeedbackEvent, (*tnl.Publisher).GetReviewerFeedbackThread,
	(*tnl.Publisher).ListReviewerFeedbackEvents,
	(*tnl.Publisher).PreparePrivateServiceRun, (*tnl.Publisher).HeartbeatPrivateServiceRun,
	(*tnl.Publisher).HeartbeatPrivateServiceRunHealth, (*tnl.Publisher).ClosePrivateServiceRun,
	(*tnl.Publisher).SavedPrivateService, (*tnl.Publisher).GetPublisherPrivateService,
	(*tnl.Publisher).CreatePrivateCertificateIssuance, (*tnl.Publisher).GetPrivateCertificateIssuance,
	(*tnl.Publisher).MarkPrivateCertificateInstalled, (*tnl.Publisher).StartManagedServiceRun,
	(*tnl.Publisher).AuthorizeServiceClientCertificate, (*tnl.Publisher).AuthorizeServiceConnector,
	(*tnl.Publisher).AuthorizeManagedHTTPVisitor, (*tnl.Publisher).RedeemManagedBrowserHandoff,
	(*tnl.Publisher).CheckManagedBrowserSession, (*tnl.Publisher).RevokeManagedBrowserSession,
}
