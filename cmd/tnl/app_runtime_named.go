package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func (a *appRuntime) startNamed(ctx context.Context, request localpublisherv1.PublicationRequest) (localpublisherv1.PublicationLease, error) {
	finish := a.manager.BeginPreparation()
	defer finish()
	if !naming.ValidServiceName(request.Service) || !privateprotocol.ValidOwner(request.Owner) || request.Pid < 1 {
		return localpublisherv1.PublicationLease{}, failure.Wrap("start named publication", failure.ProjectConfigInvalid,
			errors.New("a configured service, owner, and process ID are required"))
	}
	project, _, err := runtimeProject(ctx, runtimeOptions{Directory: a.project.Root, StateDir: a.state.Root()})
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	definition, found := project.Config.Services[request.Service]
	if !found || definition.Target == nil || definition.Target.Type != "address" && definition.Target.Type != "compose" {
		return localpublisherv1.PublicationLease{}, failure.Wrap("select named service", failure.ServiceNotConfigured,
			fmt.Errorf("service %q needs a configured address or Compose target", request.Service))
	}
	effective, err := project.EffectiveService(request.Service)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	a.prepareMu.Lock()
	defer a.prepareMu.Unlock()
	if err := a.manager.Configure(configuredRuntimeServices(project)); err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	resolver := newProjectMetadataResolver(a.state, project, strings.NewReader(""), io.Discard, "named publication")
	resolver.silent = true
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	selected := metadata.Services[request.Service]
	server, err := resolver.server(ctx, effective.Server)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	authenticated, err := resolver.client(ctx, server)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	protocol := config.ServiceProtocol(effective.Publish)
	flags := tunnelFlags{InspectionMode: config.InspectionSummary}
	applyTunnelConfiguration(&flags, effective.Tunnel, protocol)
	applyInspection(&flags, effective)
	flags.Ephemeral = false
	services, err := preparePublisherServices(ctx, a.state, server, selected.Hostname, "", flags.Domain, valueOrEmpty(effective.Team), false, authenticated)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	policy, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	var target string
	if definition.Target.Type == "compose" {
		target, err = composeTarget(project.Project, definition.Target, protocol)(ctx)
	} else if effective.Publish == nil || effective.Publish.Target == nil {
		return localpublisherv1.PublicationLease{}, failure.Wrap("resolve named service target", failure.MissingTarget, errors.New("configured address is required"))
	} else {
		target, err = normalizePublishTarget(string(*effective.Publish.Target), controlv1.PublicURLServiceProtocol(protocol))
	}
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	if protocol == "http" && definition.Target.Type != "compose" {
		options, err := targetOptionsForCA(valueOrEmpty(effective.Publish.TargetCAFile), project.Root)
		if err != nil {
			return localpublisherv1.PublicationLease{}, err
		}
		if err := localproxy.PreflightWithOptions(ctx, target, options); err != nil {
			return localpublisherv1.PublicationLease{}, err
		}
	}
	if err := projectmeta.Write(ctx, a.project.Root, metadata); err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	if err := ctx.Err(); err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	previousID := ""
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == request.Service {
			previousID = service.RegistrationID
			break
		}
	}
	snapshot, err := a.manager.JournalSnapshot()
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	id, err := a.manager.Reserve(request.Service, request.Owner, request.Pid, selected.URL)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{services: services, policy: policy, flags: flags, project: project, named: true}
	a.mu.Unlock()
	if err := a.manager.RegisterNamed(id, request.Owner, target); err != nil {
		if id != previousID {
			_ = a.manager.Unregister(id, request.Owner)
			a.mu.Lock()
			delete(a.prepared, id)
			a.mu.Unlock()
		}
		return localpublisherv1.PublicationLease{}, err
	}
	lease := localpublisherv1.PublicationLease{PublicationId: id, Service: request.Service, Cursor: snapshot.Cursor}
	if policy.current != "" {
		lease.CurrentIp = &policy.current
	}
	return lease, nil
}

func (a *appRuntime) namedHandler(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/publications", func(w http.ResponseWriter, r *http.Request) {
		var request localpublisherv1.PublicationRequest
		if err := decodeLocalRequest(w, r, &request); err != nil {
			runtimeProblem(w, err)
			return
		}
		lease, err := a.startNamed(r.Context(), request)
		if err != nil {
			runtimeProblem(w, err)
			return
		}
		privateprotocol.Write(w, http.StatusOK, lease)
	})
	for _, operation := range []string{"renew", "stop"} {
		pattern := "POST /v1/publications/{publication_id}/renew"
		if operation == "stop" {
			pattern = "DELETE /v1/publications/{publication_id}"
		}
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			id, owner := r.PathValue("publication_id"), r.Header.Get("X-Publication-Owner")
			if !privateprotocol.ValidOwner(owner) || !a.namedPublication(id) {
				runtimeProblem(w, clientruntime.ErrRegistrationStale)
				return
			}
			var err error
			if operation == "renew" {
				err = a.manager.Renew(id, owner)
			} else {
				err = a.manager.Unregister(id, owner)
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			if operation == "stop" {
				a.mu.Lock()
				delete(a.prepared, id)
				a.mu.Unlock()
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
}

func (a *appRuntime) namedPublication(id string) bool {
	for _, service := range a.manager.Snapshot().Services {
		if service.RegistrationID == id && service.ServiceProtocol != "" {
			return true
		}
	}
	return false
}
