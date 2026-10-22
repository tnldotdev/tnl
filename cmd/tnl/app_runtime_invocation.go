package main

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

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/muxsession"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (a *appRuntime) invocation(ctx context.Context, request privateprotocol.Invocation) (_ privateprotocol.Registration, result error) {
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	canonical, err := targetsyntax.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target || request.PublisherFile != "" && request.PublisherId != "" ||
		request.AccessMode != nil && !request.AccessMode.Valid() || request.Ip != nil && len(*request.Ip) > 32 {
		return privateprotocol.Registration{}, errors.New("invalid invocation target or policy")
	}
	limits, err := invocationLimits(request.Limits)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	file := request.PublisherFile
	if file == "" && request.PublisherId == "" {
		file = os.Getenv("TNL_PUBLISHER_FILE")
	}
	if file != "" && (!filepath.IsAbs(file) || len(file) > 4096 || strings.ContainsRune(file, 0)) {
		return privateprotocol.Registration{}, credentialfile.ErrInvalid
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
			return privateprotocol.Registration{}, clientruntime.ErrOwnerConflict
		}
		if err := a.manager.Renew(service.RegistrationID, request.Owner); err != nil {
			return privateprotocol.Registration{}, err
		}
		return privateprotocol.Registration{Version: 1, RegistrationID: service.RegistrationID, Owner: request.Owner, Target: request.Target}, nil
	}
	server := valueOrEmpty(a.project.Config.Server)
	if request.ServerUrl != nil {
		selected, err := clientstate.CanonicalServer(*request.ServerUrl)
		if err != nil {
			return privateprotocol.Registration{}, err
		}
		if server != "" && server != selected {
			return privateprotocol.Registration{}, nativeauth.ErrScope
		}
		server = selected
	}
	server, err = clientserver.Select(ctx, a.state, server)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	profile, err := a.state.Server(ctx, server)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	control, err := controlclient.New(server, nil, "")
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	authority, err := authorityclient.New(server, nil, "")
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	native, err := nativeauth.ResolveAdHoc(ctx, profile, control, authority, server, "", "", "", file, "", request.PublisherId, nil)
	if err != nil {
		if file != "" && errors.Is(err, nativeauth.ErrScope) {
			return privateprotocol.Registration{}, credentialfile.ErrInvalid
		}
		return privateprotocol.Registration{}, err
	}
	allocation := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: request.InvocationId, Target: request.Target, Ip: request.Ip, Limits: request.Limits}
	if request.AccessMode != nil {
		mode := controlv1.VisitorAccessMode(*request.AccessMode)
		allocation.AccessMode = &mode
	}
	route, err := native.Allocate(ctx, allocation)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	cleanup := sync.OnceValue(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return native.DeletePublicURL(ctx, route.Id)
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
	if err := a.manager.AddService(clientruntime.Service{Name: request.InvocationId, Directory: ".", ServiceProtocol: "http", Readiness: clientruntime.Readiness{Path: "/"}}); err != nil {
		return privateprotocol.Registration{}, err
	}
	id, err = a.manager.Reserve(request.InvocationId, request.Owner, request.Pid, "https://"+route.CanonicalHostname)
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	policy, err := config.ResolveInspection(nil, "http")
	if err != nil {
		return privateprotocol.Registration{}, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: route.TeamId, DomainID: route.DomainId, PublicURLScope: route.PublicUrlScope, Purpose: route.Purpose, PolicyRevision: uint64(route.PolicyRevision), Hostname: route.CanonicalHostname, ProjectRoot: a.project.Root, Target: request.Target, ServiceProtocol: "http", Limits: limits, Ephemeral: true, AllocatedPublicURL: &route, QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: tlsConfig}}
	cfg.PublisherID = native.PublisherID()
	if route.MembershipId != nil {
		cfg.MembershipID = *route.MembershipId
	}
	if route.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*route.AllowedIpPrefixes)
	}
	cfg.AccessMode = route.AccessMode
	configuration := projectpublisher.Configuration{Publisher: cfg, Inspection: policy, Cleanup: cleanup}
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, clientruntime.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}, &configuration.Publisher); err != nil {
			return privateprotocol.Registration{}, err
		}
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, invocation: &request}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return privateprotocol.Registration{}, err
	}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
		return privateprotocol.Registration{}, err
	}
	if err := ctx.Err(); err != nil {
		return privateprotocol.Registration{}, err
	}
	transferred = true
	return privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, nil
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
