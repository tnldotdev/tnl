package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func remoteProjectStatus(ctx context.Context, project projectConfiguration, probe string) (localpublisherv1.ProjectSnapshot, error) {
	endpoint, err := selectedPublisherEndpoint(ctx, project)
	if err != nil {
		return localpublisherv1.ProjectSnapshot{}, err
	}
	path := "/v1/status"
	if probe != "" {
		path += "?probe=" + url.QueryEscape(probe)
	}
	client := namedPublisherClient{endpoint: endpoint, http: publisherHTTPClient(5 * time.Second)}
	var snapshot localpublisherv1.ProjectSnapshot
	if err := client.request(ctx, http.MethodGet, path, "", nil, &snapshot); err != nil {
		return localpublisherv1.ProjectSnapshot{}, err
	}
	if snapshot.Project != project.Root {
		return localpublisherv1.ProjectSnapshot{}, failure.Wrap("select project publisher", failure.ProjectConfigInvalid,
			errors.New("publisher project directory differs; mount the worktree at the same path as the host"))
	}
	return snapshot, nil
}

func readRemoteAppSnapshot(ctx context.Context, project projectConfiguration) (clientruntime.Snapshot, error) {
	snapshot := clientruntime.Snapshot{SchemaVersion: 1, Project: project.Root, Cursor: "0", ObservedAt: time.Now().UTC(), Services: configuredRuntimeServices(project)}
	remote, err := remoteProjectStatus(ctx, project, "")
	if err != nil {
		var network *url.Error
		if !errors.As(err, &network) {
			return snapshot, err
		}
		for index := range snapshot.Services {
			snapshot.Services[index].Failure = "runtime.manager_unavailable"
		}
		return snapshot, nil
	}
	snapshot.Cursor = remote.Cursor
	for index := range snapshot.Services {
		service := &snapshot.Services[index]
		for _, status := range remote.Services {
			if status.Service != service.Name {
				continue
			}
			applyRemoteServiceStatus(service, status)
			break
		}
	}
	return snapshot, nil
}

func applyRemoteServiceStatus(service *clientruntime.Service, status localpublisherv1.ServiceStatus) {
	service.Registered = status.PublicationId != nil && status.State != localpublisherv1.NotStarted && status.State != localpublisherv1.Draining
	service.Routable = status.State == localpublisherv1.Routable || status.State == localpublisherv1.Ready
	service.Ready = status.State == localpublisherv1.Ready
	if status.TunnelId != nil {
		service.TunnelID = *status.TunnelId
	}
	if status.PublicUrl != nil {
		service.PublicURL = *status.PublicUrl
	}
	if status.Target != nil {
		service.Target = *status.Target
	}
	if status.PublicationId != nil {
		service.RegistrationID = *status.PublicationId
	}
	if status.PublishRunNumber != nil && *status.PublishRunNumber > 0 {
		service.PublishRunNumber = uint64(*status.PublishRunNumber)
	}
	if status.Reason != nil {
		service.Failure = *status.Reason
	}
}

func runRemoteAppWatch(ctx context.Context, project projectConfiguration, flags watchCommand, output io.Writer) error {
	cursor := flags.After
	if cursor == "" {
		snapshot, err := readRemoteAppSnapshot(ctx, project)
		if err != nil {
			return err
		}
		cursor = snapshot.Cursor
		if flags.Output == "ndjson" {
			if err := json.NewEncoder(output).Encode(struct {
				Type     string                 `json:"type"`
				Snapshot clientruntime.Snapshot `json:"snapshot"`
			}{"snapshot", snapshot}); err != nil {
				return err
			}
		} else if err := writeHumanFrame(output, "tnl watch", "snapshot", "cursor "+cursor, appServiceBlocks(snapshot)...); err != nil {
			return err
		}
	} else if _, err := remoteProjectStatus(ctx, project, ""); err != nil {
		return err
	}
	if _, err := clientruntime.ParseCursor(cursor); err != nil {
		return failure.Wrap("resume local events", failure.InvalidCommand, err)
	}
	endpoint, err := selectedPublisherEndpoint(ctx, project)
	if err != nil {
		return err
	}
	client := namedPublisherClient{endpoint: endpoint, http: publisherHTTPClient(5 * time.Second)}
	for ctx.Err() == nil {
		var page localpublisherv1.ProjectEventPage
		if err := client.request(ctx, http.MethodGet, "/v1/events?after="+url.QueryEscape(cursor), "", nil, &page); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, change := range page.Events {
			if change.Status == nil {
				continue
			}
			service, found := project.Config.Services[change.Service]
			if !found {
				continue
			}
			effective, err := project.EffectiveService(change.Service)
			if err != nil {
				return err
			}
			protocol := config.ServiceProtocol(effective.Publish)
			snapshot := clientruntime.Service{Name: change.Service, Directory: project.RelativeServiceDirectories[change.Service]}
			if service.Target != nil && service.Target.Type != "app" {
				snapshot.ServiceProtocol = protocol
			}
			applyRemoteServiceStatus(&snapshot, *change.Status)
			if err := writeAppWatchEvent(output, flags.Output, clientruntime.Event{
				Cursor: change.Cursor, Type: change.Type, At: change.At, Service: &snapshot,
			}); err != nil {
				return err
			}
		}
		if _, err := clientruntime.ParseCursor(page.Cursor); err != nil {
			return failure.Wrap("read publisher events", failure.ServerResponseInvalid, err)
		}
		cursor = page.Cursor
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func probeRemoteTarget(ctx context.Context, project projectConfiguration, service string) bool {
	snapshot, err := remoteProjectStatus(ctx, project, service)
	if err != nil {
		return false
	}
	for _, status := range snapshot.Services {
		if status.Service == service && status.State == localpublisherv1.Ready {
			return true
		}
	}
	return false
}
