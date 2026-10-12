package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		return localpublisherv1.PublicationLease{}, failure.Wrap("start named publication", failure.ProjectConfigInvalid, errors.New("a configured service, owner, and process ID are required"))
	}
	project, _, err := runtimeProject(ctx, runtimeOptions{Directory: a.project.Root, StateDir: a.state.Root()})
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	definition, found := project.Config.Services[request.Service]
	if !found || definition.Target == nil || definition.Target.Type == "app" {
		return localpublisherv1.PublicationLease{}, failure.Wrap("select named service", failure.ServiceNotConfigured, fmt.Errorf("service %q needs an address or Docker target", request.Service))
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
	flags := tunnelFlags{InspectionMode: config.InspectionSummary}
	applyTunnelConfiguration(&flags, effective.Tunnel)
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
	target := ""
	var resolveTarget func() string
	protocol := config.ServiceProtocol(effective.Publish)
	if definition.Target.Type == "docker" {
		if project.Config.Publisher != nil && project.Config.Publisher.Type == "docker" {
			chosen := definition.Target.Compose
			owner := project.Config.Publisher.Compose
			if chosen == nil || owner == nil || chosen.Project != project.Worktree.Label.FullLabel ||
				owner.Project != chosen.Project || owner.File != chosen.File {
				return localpublisherv1.PublicationLease{}, failure.Wrap("resolve named service target", failure.ProjectConfigInvalid,
					errors.New("docker publisher requires a target in its own Compose file and project; use an address for another network"))
			}
			target = dockerTargetInsidePublisher(chosen.Service, *definition.Target.ContainerPort, protocol == "http")
		} else {
			resolver := newDockerPublishResolver(a.manager.Context(), project.Root, dockerPublishTarget{
				selection:    definition.Target.DockerSelection,
				projectLabel: project.Worktree.Label.FullLabel,
			}, protocol == "http")
			target, err = resolver.initial()
			resolveTarget = resolver.target
		}
	} else if effective.Publish != nil && effective.Publish.Target != nil {
		target, err = normalizePublishTarget(string(*effective.Publish.Target), controlv1.PublicURLServiceProtocol(protocol))
	}
	if err != nil || target == "" {
		return localpublisherv1.PublicationLease{}, failure.Wrap("resolve named service target", failure.MissingTarget, errors.Join(err, errors.New("a reachable configured target is required")))
	}
	if protocol == "http" {
		caFile := ""
		if effective.Publish != nil && effective.Publish.TargetCAFile != nil {
			caFile = *effective.Publish.TargetCAFile
		}
		options, err := targetOptionsForCA(caFile, project.Root)
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
	cursor := a.manager.Snapshot().Cursor
	id, err := a.manager.Reserve(request.Service, request.Owner, request.Pid, selected.URL)
	if err != nil {
		return localpublisherv1.PublicationLease{}, err
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{services: services, policy: policy, flags: flags, project: project, named: true, resolve: resolveTarget}
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
	lease := localpublisherv1.PublicationLease{PublicationId: id, Service: request.Service, Cursor: cursor}
	if policy.current != "" {
		lease.CurrentIp = &policy.current
	}
	return lease, nil
}

func (a *appRuntime) namedHandler(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/publications", func(w http.ResponseWriter, r *http.Request) {
		var request localpublisherv1.PublicationRequest
		if err := privateprotocol.Decode(w, r, &request); err != nil {
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
			owner := r.Header.Get("X-Publication-Owner")
			if !privateprotocol.ValidOwner(owner) {
				runtimeProblem(w, errors.New("invalid publication owner"))
				return
			}
			var err error
			if operation == "renew" {
				err = a.manager.Renew(r.PathValue("publication_id"), owner)
			} else {
				err = a.manager.Unregister(r.PathValue("publication_id"), owner)
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		if len(values["after"]) != 1 || len(values["wait_seconds"]) > 1 {
			runtimeProblem(w, errors.New("invalid event cursor or wait"))
			return
		}
		wait := 0
		if len(values["wait_seconds"]) == 1 {
			var err error
			wait, err = strconv.Atoi(values.Get("wait_seconds"))
			if err != nil || wait < 0 || wait > 30 {
				runtimeProblem(w, errors.New("invalid event wait"))
				return
			}
		}
		if len(values.Get("after")) > 128 {
			runtimeProblem(w, errors.New("event cursor is too long"))
			return
		}
		deadline := time.Now().Add(time.Duration(wait) * time.Second)
		for {
			snapshot := a.manager.Snapshot()
			events, err := clientruntime.EventsAfter(snapshot, values.Get("after"))
			if errors.Is(err, clientruntime.ErrCursorExpired) {
				privateprotocol.Write(w, http.StatusGone, localpublisherv1.Problem{Code: "runtime.cursor_expired", Message: "local event cursor expired; read status and resume"})
				return
			}
			if err != nil {
				runtimeProblem(w, err)
				return
			}
			if len(events) != 0 || time.Now().After(deadline) || wait == 0 {
				page := localpublisherv1.ProjectEventPage{Cursor: snapshot.Cursor, Events: []localpublisherv1.ProjectEvent{}}
				for _, event := range events {
					page.Cursor = event.Cursor
					if event.Service == nil {
						continue
					}
					status := namedServiceStatus(*event.Service)
					page.Events = append(page.Events, localpublisherv1.ProjectEvent{
						Cursor: event.Cursor, Type: event.Type, Service: event.Service.Name, At: event.At, Status: &status,
						Publication: namedPublicationEvent(event.Publication),
					})
					if len(page.Events) >= 32 {
						break
					}
				}
				privateprotocol.Write(w, http.StatusOK, page)
				return
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	})
}

func namedProjectSnapshot(snapshot clientruntime.Snapshot) localpublisherv1.ProjectSnapshot {
	result := localpublisherv1.ProjectSnapshot{Project: snapshot.Project, Cursor: snapshot.Cursor, Services: make([]localpublisherv1.ServiceStatus, 0, len(snapshot.Services))}
	for _, service := range snapshot.Services {
		result.Services = append(result.Services, namedServiceStatus(service))
	}
	return result
}

func namedServiceStatus(service clientruntime.Service) localpublisherv1.ServiceStatus {
	protocol := service.ServiceProtocol
	if protocol == "" {
		protocol = "http"
	}
	state := localpublisherv1.NotStarted
	switch {
	case service.Ready:
		state = localpublisherv1.Ready
	case service.Routable:
		state = localpublisherv1.Routable
	case service.Registered:
		state = localpublisherv1.Publishing
	case service.Failure != "":
		state = localpublisherv1.Failed
	}
	result := localpublisherv1.ServiceStatus{Service: service.Name, Protocol: localpublisherv1.ServiceStatusProtocol(protocol), State: state}
	if service.Target != "" {
		result.Target = &service.Target
	}
	if service.PublicURL != "" {
		result.PublicUrl = &service.PublicURL
	}
	if service.RegistrationID != "" {
		result.PublicationId = &service.RegistrationID
	}
	if service.TunnelID != "" {
		result.TunnelId = &service.TunnelID
	}
	if service.PublishRunNumber != 0 {
		number := int64(service.PublishRunNumber)
		result.PublishRunNumber = &number
	}
	if service.Failure != "" {
		result.Reason = &service.Failure
	}
	return result
}

func namedPublicationEvent(event *clientruntime.PublicationEvent) *localpublisherv1.PublicationEvent {
	if event == nil {
		return nil
	}
	result := &localpublisherv1.PublicationEvent{Type: event.Type}
	if event.PublicURLID != "" {
		result.PublicUrlId = &event.PublicURLID
	}
	if event.Hostname != "" {
		result.Hostname = &event.Hostname
	}
	if event.PublicURL != "" {
		result.PublicUrl = &event.PublicURL
	}
	if event.PublishRunNumber != 0 {
		number := int64(event.PublishRunNumber)
		result.PublishRunNumber = &number
	}
	if event.Transport != "" {
		transport := localpublisherv1.PublicationEventTransport(event.Transport)
		result.Transport = &transport
	}
	if event.PolicyDenials != 0 {
		count := int64(event.PolicyDenials)
		result.PolicyDenials = &count
	}
	return result
}
