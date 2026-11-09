package local

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *appRuntime) invocation(ctx context.Context, request publisherprotocol.Invocation) (_ publisherprotocol.Registration, result error) {
	return a.prepareInvocation(ctx, request, true)
}

func (a *appRuntime) preparePublication(ctx context.Context, request publisherprotocol.PreparePublication) (publisherprotocol.PublicationAssignment, error) {
	if request.Version != 1 || request.ApplicationCredential == "" {
		return publisherprotocol.PublicationAssignment{}, credentialfile.ErrApplication
	}
	registration, err := a.prepareInvocation(ctx, publisherprotocol.Invocation{Version: 1, InvocationId: request.InvocationId, Owner: request.Owner, Pid: request.Pid, ServerUrl: request.ServerUrl, ApplicationCredential: &request.ApplicationCredential, ResourceId: &request.ResourceId}, false)
	if err != nil {
		return publisherprotocol.PublicationAssignment{}, err
	}
	service, found := a.manager.ServiceForRegistration(registration.RegistrationID)
	if !found {
		return publisherprotocol.PublicationAssignment{}, publisherapp.ErrRegistrationStale
	}
	hostname := strings.TrimPrefix(service.PublicURL, "https://")
	a.mu.Lock()
	if preparation := a.prepared[registration.RegistrationID]; preparation.servicePublication != nil {
		hostname = preparation.servicePublication.Saved.Endpoint.Hostname
	}
	a.mu.Unlock()
	return publisherprotocol.PublicationAssignment{Version: 1, RegistrationID: registration.RegistrationID, ResourceId: request.ResourceId, Hostname: hostname, PublicUrl: service.PublicURL}, nil
}

func (a *appRuntime) registerPublication(ctx context.Context, request publisherprotocol.Registration) error {
	canonical, err := targetsyntax.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target {
		return publisherprotocol.ErrForbidden
	}
	a.mu.Lock()
	preparation, found := a.prepared[request.RegistrationID]
	a.mu.Unlock()
	if !found || !preparation.preparedPublication || preparation.invocation == nil {
		return publisherprotocol.ErrForbidden
	}
	return a.manager.RegisterContext(ctx, request.RegistrationID, request.Owner, request.Target, "")
}

func (a *appRuntime) prepareInvocation(ctx context.Context, request publisherprotocol.Invocation, bound bool) (_ publisherprotocol.Registration, result error) {
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	canonical := request.Target
	if bound {
		canonical, err = targetsyntax.NormalizeTarget(request.Target)
	} else if request.Target != "" || request.ApplicationCredential == nil {
		return publisherprotocol.Registration{}, credentialfile.ErrApplication
	}
	if err != nil || canonical != request.Target || request.PublisherCredentialFile != "" && request.PublisherIdentityId != "" ||
		request.AccessMode != nil && !request.AccessMode.Valid() || request.Ip != nil && len(*request.Ip) > 32 {
		return publisherprotocol.Registration{}, errors.New("invalid invocation target or policy")
	}
	var application *credentialfile.File
	if request.ApplicationCredential != nil {
		if request.PublisherCredentialFile != "" || request.PublisherIdentityId != "" {
			return publisherprotocol.Registration{}, credentialfile.ErrApplication
		}
		parsed, err := credentialfile.Parse([]byte(*request.ApplicationCredential))
		if err != nil {
			return publisherprotocol.Registration{}, errors.Join(credentialfile.ErrApplication, err)
		}
		if request.ResourceId == nil || !opaqueid.Valid(*request.ResourceId, opaqueid.PublicURLPrefix) && !opaqueid.Valid(*request.ResourceId, opaqueid.ServicePrefix) {
			return publisherprotocol.Registration{}, credentialfile.ErrGrant
		}
		application = &parsed
	} else if request.ResourceId != nil {
		return publisherprotocol.Registration{}, credentialfile.ErrApplication
	}
	limits, err := invocationLimits(request.Limits)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	file := request.PublisherCredentialFile
	if application == nil && file == "" && request.PublisherIdentityId == "" {
		file = os.Getenv("TNL_PUBLISHER_CREDENTIAL_FILE")
	}
	if file != "" && (!filepath.IsAbs(file) || len(file) > 4096 || strings.ContainsRune(file, 0)) {
		return publisherprotocol.Registration{}, credentialfile.ErrInvalid
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name != request.InvocationId || service.RegistrationID == "" {
			continue
		}
		a.mu.Lock()
		preparation := a.prepared[service.RegistrationID]
		previous := preparation.invocation
		a.mu.Unlock()
		comparison := previous
		if previous != nil && (!bound || preparation.preparedPublication && service.Target == request.Target) {
			copy := *previous
			copy.Target = request.Target
			comparison = &copy
		}
		first, _ := json.Marshal(comparison)
		next, _ := json.Marshal(request)
		if previous == nil || string(first) != string(next) {
			return publisherprotocol.Registration{}, publisherapp.ErrOwnerConflict
		}
		if err := a.manager.Renew(service.RegistrationID, request.Owner); err != nil {
			return publisherprotocol.Registration{}, err
		}
		return publisherprotocol.Registration{Version: 1, RegistrationID: service.RegistrationID, Owner: request.Owner, Target: request.Target}, nil
	}
	server := valueOrEmpty(a.project.Config.Server)
	if application != nil {
		server = application.ControlURL
	}
	if request.ServerUrl != nil {
		selected, err := clientstate.CanonicalServer(*request.ServerUrl)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		if server != "" && server != selected {
			if application != nil {
				return publisherprotocol.Registration{}, credentialfile.ErrGrant
			}
			return publisherprotocol.Registration{}, publisheridentity.ErrScope
		}
		server = selected
	}
	server, err = clientserver.Select(ctx, a.state, server)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	profile, err := a.state.Server(ctx, server)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	control, err := clientcontrol.New(server, nil, "")
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	authority, err := clientauthority.New(server, nil, "")
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	var native *publisheridentity.Native
	var selectedIdentity authorityv1.PublisherEnrollmentResult
	if application != nil {
		grant, err := application.Select(controlv1.ApplicationPublish, *request.ResourceId)
		if err != nil || grant.Kind != "saved_public_url" && grant.Kind != "service" || grant.ExpiresAt != nil && !grant.ExpiresAt.After(time.Now()) {
			return publisherprotocol.Registration{}, credentialfile.ErrGrant
		}
		selected := *application
		selected.Grants = []credentialfile.Grant{grant}
		identity, key, err := selected.Publisher(*request.ResourceId)
		if err != nil {
			return publisherprotocol.Registration{}, errors.Join(credentialfile.ErrApplication, err)
		}
		selectedIdentity = identity
		native, err = publisheridentity.NewNative(control, authority, identity, key)
		clear(key)
		if err != nil {
			return publisherprotocol.Registration{}, errors.Join(credentialfile.ErrApplication, err)
		}
	} else {
		native, err = publisheridentity.ResolveAdHoc(ctx, profile, control, authority, server, "", "", "", file, "", request.PublisherIdentityId, nil)
	}
	if err != nil {
		if file != "" && errors.Is(err, publisheridentity.ErrScope) {
			return publisherprotocol.Registration{}, credentialfile.ErrInvalid
		}
		return publisherprotocol.Registration{}, err
	}
	if application != nil && selectedIdentity.Kind == authorityv1.Service {
		return a.prepareApplicationService(ctx, request, bound, profile, native, selectedIdentity)
	}
	allocation := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: request.InvocationId, Target: request.Target, Ip: request.Ip, Limits: request.Limits}
	allocation.RequirePostQuantum = request.RequirePostQuantum
	if request.AccessMode != nil {
		mode := controlv1.VisitorAccessMode(*request.AccessMode)
		allocation.AccessMode = &mode
	}
	var publicURL controlv1.PublicURL
	if application != nil {
		publicURL, err = native.SavedPublicURL(ctx)
		if err != nil {
			return publisherprotocol.Registration{}, applicationAuthorityError(err)
		}
		if publicURL.Ephemeral || publicURL.ServiceProtocol != controlv1.Http || publicURL.Purpose != controlv1.App || request.AccessMode != nil || request.Ip != nil || request.RequirePostQuantum != nil && *request.RequirePostQuantum != publicURL.RequirePostQuantum {
			return publisherprotocol.Registration{}, credentialfile.ErrGrant
		}
	} else {
		publicURL, err = native.Allocate(ctx, allocation)
	}
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	cleanup := sync.OnceValue(func() error {
		if application != nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return native.DeletePublicURL(ctx, publicURL.Id)
	})
	transferred, id := false, ""
	defer func() {
		if !transferred {
			if id != "" {
				result = errors.Join(result, a.manager.Unregister(id, request.Owner))
				a.mu.Lock()
				delete(a.prepared, id)
				a.mu.Unlock()
			}
			result = errors.Join(result, cleanup())
		}
	}()
	if err := a.manager.AddService(publisherapp.Service{Name: request.InvocationId, Directory: ".", ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/"}}); err != nil {
		return publisherprotocol.Registration{}, err
	}
	id, err = a.manager.Reserve(request.InvocationId, request.Owner, request.Pid, "https://"+publicURL.CanonicalHostname)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	policy, err := config.ResolveInspection(nil, "http")
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, PolicyRevision: uint64(publicURL.PolicyRevision), Hostname: publicURL.CanonicalHostname, ProjectRoot: a.project.Root, Target: request.Target, ServiceProtocol: "http", Limits: limits, Ephemeral: publicURL.Ephemeral, AssignedPublicURL: &publicURL, QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: tlsConfig}}
	cfg.PublisherIdentityID = native.PublisherIdentityID()
	cfg.RequirePostQuantum = request.RequirePostQuantum
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	cfg.AccessMode = publicURL.AccessMode
	configuration := publisherapp.Configuration{Publisher: cfg, Inspection: policy, Cleanup: cleanup}
	if bound && a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, publisherapp.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}, &configuration.Publisher); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, invocation: &request, preparedPublication: !bound}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	if bound {
		if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	transferred = true
	return publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, nil
}

func applicationAuthorityError(err error) error {
	reason, _ := failure.ReasonOf(err)
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, publisheridentity.ErrScope) || reason == failure.ServerDenied || reason == failure.Authentication {
		return errors.Join(credentialfile.ErrGrant, err)
	}
	if reason == failure.ServerResponseInvalid {
		return errors.Join(credentialfile.ErrApplication, err)
	}
	return errors.Join(credentialfile.ErrApplicationUnavailable, err)
}

func invocationLimits(input *controlv1.PublisherApplicationLimits) (publisher.ApplicationLimits, error) {
	var limits publisher.ApplicationLimits
	if input != nil {
		if input.Requests != nil {
			if *input.Requests < 1 {
				return limits, errors.New("request limit must be positive")
			}
			limits.Requests = *input.Requests
		}
		if input.Concurrency != nil {
			if *input.Concurrency < 1 {
				return limits, errors.New("concurrency limit must be positive")
			}
			limits.Concurrency = *input.Concurrency
		}
		if input.Rate != nil {
			period, err := time.ParseDuration(input.Rate.Per)
			if err != nil || period <= 0 || input.Rate.Requests < 1 {
				return limits, errors.New("request rate requires a positive count and period")
			}
			limits.RateRequests, limits.RatePer = input.Rate.Requests, period
		}
	}
	return limits, limits.Validate()
}
