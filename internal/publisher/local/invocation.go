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
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *appRuntime) invocation(ctx context.Context, request publisherprotocol.Invocation) (_ publisherprotocol.Registration, result error) {
	// capture before preparation can wait or call application-owned hooks. the
	// retained request must not borrow the caller's optional boolean either.
	telemetryDisabled := request.TelemetryDisabled != nil && *request.TelemetryDisabled
	request.TelemetryDisabled = &telemetryDisabled
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	canonical, err := targetsyntax.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target || request.PublisherCredentialFile != "" && request.PublisherIdentityId != "" ||
		request.AccessMode != nil && !request.AccessMode.Valid() || request.Ip != nil && len(*request.Ip) > 32 {
		return publisherprotocol.Registration{}, errors.New("invalid invocation target or policy")
	}
	limits, err := invocationLimits(request.Limits)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	file := request.PublisherCredentialFile
	if file == "" && request.PublisherIdentityId == "" {
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
		previous := a.prepared[service.RegistrationID].invocation
		a.mu.Unlock()
		first, _ := json.Marshal(previous)
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
	if request.ServerUrl != nil {
		selected, err := clientstate.CanonicalServer(*request.ServerUrl)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		if server != "" && server != selected {
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
	native, err := publisheridentity.ResolveAdHoc(ctx, profile, control, authority, server, "", "", "", file, "", request.PublisherIdentityId, nil)
	if err != nil {
		if file != "" && errors.Is(err, publisheridentity.ErrScope) {
			return publisherprotocol.Registration{}, credentialfile.ErrInvalid
		}
		return publisherprotocol.Registration{}, err
	}
	allocation := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: request.InvocationId, Target: request.Target, Ip: request.Ip, Limits: request.Limits}
	if request.AccessMode != nil {
		mode := controlv1.VisitorAccessMode(*request.AccessMode)
		allocation.AccessMode = &mode
	}
	publicURL, err := native.Allocate(ctx, allocation)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	cleanup := sync.OnceValue(func() error {
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
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, PolicyRevision: uint64(publicURL.PolicyRevision), Hostname: publicURL.CanonicalHostname, ProjectRoot: a.project.Root, Target: request.Target, ServiceProtocol: "http", Limits: limits, Ephemeral: true, AssignedPublicURL: &publicURL, QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: tlsConfig}}
	cfg.PublisherIdentityID = native.PublisherIdentityID()
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	cfg.AccessMode = publicURL.AccessMode
	configuration := publisherapp.Configuration{Publisher: cfg, Inspection: policy, Cleanup: cleanup}
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, publisherapp.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}, &configuration.Publisher); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, invocation: &request, telemetryDisabled: telemetryDisabled}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
		return publisherprotocol.Registration{}, err
	}
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	transferred = true
	return publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, nil
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
