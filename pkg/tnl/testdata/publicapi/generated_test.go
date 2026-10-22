package publicapi_test

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
	"github.com/tnldotdev/tnl/pkg/api/publicurlusagev1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

// all seven baseline generated import paths remain usable for clients,
// response clients, request editors, and server adapters.
var (
	_ func(string, ...authorityv1.ClientOption) (*authorityv1.Client, error)                        = authorityv1.NewClient
	_ func(string, ...authorityv1.ClientOption) (*authorityv1.ClientWithResponses, error)           = authorityv1.NewClientWithResponses
	_ authorityv1.ClientInterface                                                                   = (*authorityv1.Client)(nil)
	_ authorityv1.ClientWithResponsesInterface                                                      = (*authorityv1.ClientWithResponses)(nil)
	_ func(authorityv1.ServerInterface) http.Handler                                                = authorityv1.Handler
	_ authorityv1.RequestEditorFn                                                                   = editRequest
	_ func(string, ...controlv1.ClientOption) (*controlv1.Client, error)                            = controlv1.NewClient
	_ func(string, ...controlv1.ClientOption) (*controlv1.ClientWithResponses, error)               = controlv1.NewClientWithResponses
	_ controlv1.ClientInterface                                                                     = (*controlv1.Client)(nil)
	_ controlv1.ClientWithResponsesInterface                                                        = (*controlv1.ClientWithResponses)(nil)
	_ func(controlv1.ServerInterface) http.Handler                                                  = controlv1.Handler
	_ controlv1.RequestEditorFn                                                                     = editRequest
	_ func(string, ...ingressv1.ClientOption) (*ingressv1.Client, error)                            = ingressv1.NewClient
	_ func(string, ...ingressv1.ClientOption) (*ingressv1.ClientWithResponses, error)               = ingressv1.NewClientWithResponses
	_ ingressv1.ClientInterface                                                                     = (*ingressv1.Client)(nil)
	_ ingressv1.ClientWithResponsesInterface                                                        = (*ingressv1.ClientWithResponses)(nil)
	_ func(ingressv1.ServerInterface) http.Handler                                                  = ingressv1.Handler
	_ ingressv1.RequestEditorFn                                                                     = editRequest
	_ func(string, ...relayv1.ClientOption) (*relayv1.Client, error)                                = relayv1.NewClient
	_ func(string, ...relayv1.ClientOption) (*relayv1.ClientWithResponses, error)                   = relayv1.NewClientWithResponses
	_ relayv1.ClientInterface                                                                       = (*relayv1.Client)(nil)
	_ relayv1.ClientWithResponsesInterface                                                          = (*relayv1.ClientWithResponses)(nil)
	_ func(relayv1.ServerInterface) http.Handler                                                    = relayv1.Handler
	_ relayv1.RequestEditorFn                                                                       = editRequest
	_ func(string, ...publicurlusagev1.ClientOption) (*publicurlusagev1.Client, error)              = publicurlusagev1.NewClient
	_ func(string, ...publicurlusagev1.ClientOption) (*publicurlusagev1.ClientWithResponses, error) = publicurlusagev1.NewClientWithResponses
	_ publicurlusagev1.ClientInterface                                                              = (*publicurlusagev1.Client)(nil)
	_ publicurlusagev1.ClientWithResponsesInterface                                                 = (*publicurlusagev1.ClientWithResponses)(nil)
	_ func(publicurlusagev1.ServerInterface) http.Handler                                           = publicurlusagev1.Handler
	_ publicurlusagev1.RequestEditorFn                                                              = editRequest
	_ func(string, ...publisherv1.ClientOption) (*publisherv1.Client, error)                        = publisherv1.NewClient
	_ func(string, ...publisherv1.ClientOption) (*publisherv1.ClientWithResponses, error)           = publisherv1.NewClientWithResponses
	_ publisherv1.ClientInterface                                                                   = (*publisherv1.Client)(nil)
	_ publisherv1.ClientWithResponsesInterface                                                      = (*publisherv1.ClientWithResponses)(nil)
	_ func(publisherv1.ServerInterface) http.Handler                                                = publisherv1.Handler
	_ publisherv1.RequestEditorFn                                                                   = editRequest
	_ func(string, ...localpublisherv1.ClientOption) (*localpublisherv1.Client, error)              = localpublisherv1.NewClient
	_ func(string, ...localpublisherv1.ClientOption) (*localpublisherv1.ClientWithResponses, error) = localpublisherv1.NewClientWithResponses
	_ localpublisherv1.ClientInterface                                                              = (*localpublisherv1.Client)(nil)
	_ localpublisherv1.ClientWithResponsesInterface                                                 = (*localpublisherv1.ClientWithResponses)(nil)
	_ func(localpublisherv1.ServerInterface) http.Handler                                           = localpublisherv1.Handler
	_ localpublisherv1.RequestEditorFn                                                              = editRequest
)

func editRequest(context.Context, *http.Request) error { return nil }

// representative operations pin request aliases, ID arguments, variadic request
// editors, and HTTP response types across the seven distinct client packages.
var (
	_ func(*authorityv1.Client, context.Context, authorityv1.RedeemPublisherEnrollmentJSONRequestBody, ...authorityv1.RequestEditorFn) (*http.Response, error)                        = (*authorityv1.Client).RedeemPublisherEnrollment
	_ func(*controlv1.Client, context.Context, controlv1.PublicURLID, ...controlv1.RequestEditorFn) (*http.Response, error)                                                           = (*controlv1.Client).GetPublicURL
	_ func(*ingressv1.Client, context.Context, ingressv1.RegisterIngressJSONRequestBody, ...ingressv1.RequestEditorFn) (*http.Response, error)                                        = (*ingressv1.Client).RegisterIngress
	_ func(*relayv1.Client, context.Context, relayv1.RegisterRelayJSONRequestBody, ...relayv1.RequestEditorFn) (*http.Response, error)                                                = (*relayv1.Client).RegisterRelay
	_ func(*publicurlusagev1.Client, context.Context, publicurlusagev1.IngestPublicURLUsageBucketReportsJSONRequestBody, ...publicurlusagev1.RequestEditorFn) (*http.Response, error) = (*publicurlusagev1.Client).IngestPublicURLUsageBucketReports
	_ func(*publisherv1.Client, context.Context, ...publisherv1.RequestEditorFn) (*http.Response, error)                                                                              = (*publisherv1.Client).GetBrowserAccessStatus
	_ func(*localpublisherv1.Client, context.Context, localpublisherv1.IssueCapabilityJSONRequestBody, ...localpublisherv1.RequestEditorFn) (*http.Response, error)                   = (*localpublisherv1.Client).IssueCapability
)

// typed assignments catch enum renames or moves that string literals and
// explicit conversions would hide. referenced schemas remain public Go types.
const (
	_ authorityv1.PublisherEnrollmentResultKind             = authorityv1.Namespace
	_ authorityv1.PublisherEnrollmentResultKind             = authorityv1.SavedUrl
	_ authorityv1.PublisherEnrollmentResultKind             = authorityv1.PrivateService
	_ controlv1.VisitorAccessMode                           = controlv1.Anonymous
	_ controlv1.VisitorAccessMode                           = controlv1.Restricted
	_ controlv1.PublicURLServiceProtocol                    = controlv1.Http
	_ controlv1.PublicURLLifecycleState                     = controlv1.Enabled
	_ controlv1.PublicURLScope                              = controlv1.Member
	_ controlv1.PublicURLScope                              = controlv1.Shared
	_ controlv1.PublicURLPurpose                            = controlv1.App
	_ controlv1.PublicURLPurpose                            = controlv1.Oauth
	_ controlv1.PublicURLPurpose                            = controlv1.Webhooks
	_ controlv1.PublicURLPurpose                            = controlv1.Alias
	_ controlv1.PublisherGrantKind                          = controlv1.PublisherGrantKindNamespace
	_ ingressv1.IngressRoutingTableEntryAccessMode          = ingressv1.Anonymous
	_ ingressv1.IngressRoutingTableEntryAccessMode          = ingressv1.Restricted
	_ ingressv1.IngressRoutingTableEntryIpPolicy            = ingressv1.HashedAllowlist
	_ ingressv1.IngressRoutingTableEntryServiceProtocol     = ingressv1.Http
	_ ingressv1.IngressRoutingTableEventKind                = ingressv1.PublicUrlUpsert
	_ relayv1.ClaimedPublisherConnectionState               = relayv1.Ready
	_ relayv1.ProblemCode                                   = relayv1.StaleConnectionAssignment
	_ publicurlusagev1.PublicURLUsageBucketReportResolution = publicurlusagev1.Minute
	_ publicurlusagev1.PublicURLUsageBucketReportResolution = publicurlusagev1.Hour
	_ publicurlusagev1.ProblemCode                          = publicurlusagev1.ProblemCodeUnauthenticated
	_ publisherv1.BrowserAccessStatusAccessMethod           = publisherv1.Share
	_ publisherv1.BrowserFeedbackEventRequestType           = publisherv1.Reply
	_ localpublisherv1.EndpointVersion                      = localpublisherv1.EndpointVersionN1
	_ localpublisherv1.EndpointScope                        = localpublisherv1.EndpointScopeOwner
	_ localpublisherv1.CapabilityRequestScope               = localpublisherv1.CapabilityRequestScopeApp
	_ localpublisherv1.PrepareFramework                     = localpublisherv1.Node
	_ localpublisherv1.PrepareVersion                       = localpublisherv1.PrepareVersionN1
	_ localpublisherv1.InvocationVersion                    = localpublisherv1.InvocationVersionN1
	_ localpublisherv1.InvocationAccessMode                 = localpublisherv1.Restricted
)

var (
	_                      = authorityv1.PublisherEnrollmentResult{Kind: authorityv1.Namespace, ClientId: "publisher", GrantId: "grant", KeyId: "key", TeamId: "team", Namespace: new("member.example"), DomainId: new("domain")}
	_                      = controlv1.PublicURL{Id: "url", TeamId: "team", AccessMode: controlv1.Restricted, LifecycleState: controlv1.Enabled, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, PublicUrlScope: controlv1.Member}
	_                      = ingressv1.IngressRoutingTableEvent{Kind: ingressv1.PublicUrlUpsert, Entry: ingressv1.IngressRoutingTableEntry{AccessMode: ingressv1.Restricted, IpPolicy: ingressv1.HashedAllowlist, ServiceProtocol: new(ingressv1.Http)}}
	_                      = ingressv1.IngressTransportCertificate{Trust: controlv1.IngressTransportTrust{}}
	_                      = relayv1.ClaimedPublisherConnection{State: relayv1.Ready, PublicUrlId: controlv1.PublicURLID("url"), PublishRunNumber: 1}
	_                      = publicurlusagev1.PublicURLUsageBucketReport{PublicUrlId: controlv1.PublicURLID("url"), TeamId: controlv1.TeamID("team"), PublishRunNumber: "1", ReportRevision: "1", IngressBytes: "0", Resolution: publicurlusagev1.Minute}
	_                      = publisherv1.BrowserAccessStatus{AccessMethod: new(publisherv1.Share), PublicUrlId: controlv1.PublicURLID("url"), PreviewId: controlv1.PreviewID("preview"), SchemaVersion: controlv1.ReviewSchemaVersion(1)}
	_                      = publisherv1.BrowserFeedbackReportRequest{Evidence: controlv1.FeedbackEvidence{}, Anchor: &controlv1.FeedbackAnchor{}}
	_                      = publisherv1.BrowserFeedbackEventRequest{Type: publisherv1.Reply, SchemaVersion: controlv1.ReviewSchemaVersion(1)}
	_                      = localpublisherv1.Endpoint{Version: localpublisherv1.EndpointVersionN1, Scope: localpublisherv1.EndpointScopeOwner, Url: "http://127.0.0.1:3000", OwnerId: "owner", Capability: "capability"}
	_                      = localpublisherv1.Prepare{Version: localpublisherv1.PrepareVersionN1, Framework: localpublisherv1.Node, Directory: "/project", Owner: "owner", PID: 1}
	_                      = localpublisherv1.Invocation{Version: localpublisherv1.InvocationVersionN1, AccessMode: new(localpublisherv1.Restricted), Limits: &controlv1.PublisherApplicationLimits{}}
	_ string               = publicurlusagev1.UnsignedInteger("0")
	_ string               = relayv1.PrivateServiceID("service")
	_ controlv1.FeedbackID = publisherv1.FeedbackID("feedback")
)
