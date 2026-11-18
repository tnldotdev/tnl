package deployment

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type HandlerControl interface {
	publisheridentity.DeploymentPublicationControl
	publisheridentity.DeploymentAllocationControl
}

// HandlerOptions selects an inline HTTP application using an explicit deployment
// signing credential. it has no local project, target socket, or enrollment path.
type HandlerOptions struct {
	Control    HandlerControl
	Authority  publisheridentity.AssertionExchanger
	Approval   controlv1.DeploymentCredential
	Private    ed25519.PrivateKey
	Deployment string
	Service    string
	Handler    http.Handler
	Temporary  *TemporaryHandlerOptions
}

type TemporaryHandlerOptions struct {
	Public             *bool
	RequirePostQuantum bool
	AccessMode         controlv1.VisitorAccessMode
	IP                 []string
	Limits             *controlv1.ProjectHTTPApplicationLimits
}

func (HandlerOptions) String() string   { return "deployment handler options" }
func (HandlerOptions) GoString() string { return "deployment handler options" }

// PreparedHandler owns only its temporary allocation, if any. the caller
// supplies protected certificate storage, runs service.Publish with Config,
// joins that run, then calls Cleanup even when preparation returned an error.
type PreparedHandler struct {
	Service controlv1.Service
	Config  publisherservice.RunConfig
	mu      sync.Mutex
	native  *publisheridentity.Native
	request *controlv1.AllocateServiceRequest
}

func (*PreparedHandler) String() string   { return "prepared deployment handler" }
func (*PreparedHandler) GoString() string { return "prepared deployment handler" }

func PrepareHandler(ctx context.Context, options HandlerOptions) (*PreparedHandler, error) {
	if options.Handler == nil || options.Service != "" && options.Temporary != nil {
		return nil, publisheridentity.ErrScope
	}
	var native *publisheridentity.Native
	var saved controlv1.Service
	var prepared *PreparedHandler
	var err error
	if options.Service != "" {
		var selected *controlv1.Service
		native, selected, err = publisheridentity.PrepareDeployment(ctx, options.Control, options.Authority, options.Approval, options.Private, options.Deployment, options.Service)
		if err != nil {
			return nil, err
		}
		saved, prepared = *selected, &PreparedHandler{native: native}
	} else {
		request, err := handlerAllocation(options.Approval.ExpiresAt, options.Temporary)
		if err != nil {
			return nil, err
		}
		native, err = publisheridentity.NewDeploymentAllocator(options.Control, options.Authority, options.Approval, options.Private, options.Deployment)
		if err != nil {
			return nil, err
		}
		// capture cleanup before the first request, including an ambiguous
		// allocation reply. Native owns exact invocation recovery and deletion.
		prepared = &PreparedHandler{native: native, request: &request}
		saved, err = native.AllocateService(ctx, request)
		if err != nil {
			return prepared, err
		}
		if err := matchHandlerAllocation(saved, request); err != nil {
			return prepared, err
		}
	}
	if saved.Endpoint == nil || !serviceendpoint.Valid("http", saved.Endpoint.Hostname, saved.Endpoint.Port, saved.Endpoint.Public) {
		return prepared, publisheridentity.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, "http", nil); err != nil {
		return prepared, err
	}
	// snapshots and mutable caller options cannot alter the run metadata
	// or the captured allocation used later for cleanup.
	data, err := json.Marshal(saved)
	if err != nil {
		return prepared, err
	}
	var publication controlv1.Service
	if err := json.Unmarshal(data, &publication); err != nil {
		return prepared, err
	}
	if err := json.Unmarshal(data, &prepared.Service); err != nil {
		return prepared, err
	}
	prepared.Config = publisherservice.RunConfig{
		Control: native, Access: native.Access, Handler: options.Handler,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: publication.Id, Metadata: publisheridentity.ServiceMetadata(publication),
	}
	return prepared, nil
}

func (p *PreparedHandler) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.request == nil {
		return nil
	}
	return p.native.CleanupServiceAllocation(ctx, *p.request)
}

func handlerAllocation(expires time.Time, options *TemporaryHandlerOptions) (controlv1.AllocateServiceRequest, error) {
	var request controlv1.AllocateServiceRequest
	if options == nil {
		options = &TemporaryHandlerOptions{}
	}
	if !expires.After(time.Now()) {
		return request, publisheridentity.ErrScope
	}
	if _, err := requestlimit.ParseLimits(options.Limits); err != nil {
		return request, err
	}
	mode := options.AccessMode
	if mode == "" {
		mode = controlv1.Restricted
	}
	if mode != controlv1.Restricted && mode != controlv1.Anonymous {
		return request, publisheridentity.ErrScope
	}
	prefixes, err := authorization.CanonicalizeIPPrefixes(options.IP)
	if err != nil {
		return request, err
	}
	if options.IP != nil && len(prefixes) == 0 {
		return request, publisheridentity.ErrScope
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return request, err
	}
	request = controlv1.AllocateServiceRequest{
		InvocationId: invocation, ExpiresAt: new(expires.UTC()),
		Configuration: controlv1.ProjectServiceConfiguration{
			Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app",
			Public: new(options.Public == nil || *options.Public), Ephemeral: new(true), RequirePostQuantum: new(options.RequirePostQuantum),
			Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}, Limits: options.Limits},
		},
	}
	if options.IP != nil {
		request.Configuration.Http.Access.Ip = &prefixes
	}
	// freeze pointer-backed settings before any allocation attempt.
	data, err := json.Marshal(request)
	if err == nil {
		var frozen controlv1.AllocateServiceRequest
		err = json.Unmarshal(data, &frozen)
		request = frozen
	}
	return request, err
}

func matchHandlerAllocation(saved controlv1.Service, request controlv1.AllocateServiceRequest) error {
	if saved.RequirePostQuantum != *request.Configuration.RequirePostQuantum || !saved.Ephemeral ||
		saved.ExpiresAt == nil || !saved.ExpiresAt.After(time.Now()) || saved.ExpiresAt.After(*request.ExpiresAt) {
		return publisheridentity.ErrScope
	}
	approved, err := requestlimit.ParseLimits(saved.HttpLimits)
	if err != nil {
		return err
	}
	requested, err := requestlimit.ParseLimits(request.Configuration.Http.Limits)
	if err != nil {
		return err
	}
	if requested.Requests != 0 && approved.Requests != requested.Requests ||
		requested.Concurrency != 0 && approved.Concurrency != requested.Concurrency ||
		requested.RateRequests != 0 && (approved.RateRequests != requested.RateRequests || approved.RatePer != requested.RatePer) ||
		requested.RateBurst != 0 && approved.RateBurst != requested.RateBurst {
		return publisheridentity.ErrScope
	}
	return nil
}
