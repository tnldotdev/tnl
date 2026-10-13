package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

type waitCommand struct {
	StateDir string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Service  []string      `name:"service" help:"Check this service; repeat to select several. Defaults to every configured service."`
	Timeout  time.Duration `name:"timeout" default:"2m" help:"Time to wait for fresh readiness checks."`
	Output   string        `name:"output" enum:"human,json" default:"human"`
}
type watchCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	After    string `name:"after" help:"Resume after this local event cursor. Without it, show current services before following new events."`
	Output   string `name:"output" enum:"human,ndjson" default:"human"`
}

func readAppSnapshot(ctx context.Context, project projectConfiguration, state string) (clientruntime.Snapshot, error) {
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		return readRemoteAppSnapshot(ctx, project)
	}
	snapshot, err := clientruntime.ReadSnapshot(project.Root, state)
	if err != nil {
		return snapshot, err
	}
	configured := configuredRuntimeServices(project)
	for index := range configured {
		for _, saved := range snapshot.Services {
			if saved.Name == configured[index].Name {
				current := configured[index]
				configured[index] = saved
				configured[index].Directory = current.Directory
				configured[index].Readiness = current.Readiness
				if saved.Readiness != current.Readiness {
					configured[index].Ready = false
					configured[index].Observation = nil
				}
				break
			}
		}
	}
	snapshot.Services = configured
	for index := range snapshot.Services {
		service := &snapshot.Services[index]
		selected := project.Config.Services[service.Name].Target
		if selected == nil || selected.Type != "docker" {
			continue
		}
		resolver := newDockerPublishResolver(ctx, project.Root, dockerPublishTarget{
			selection: selected.DockerSelection, projectLabel: project.Worktree.Label.FullLabel,
		}, service.ServiceProtocol == "" || service.ServiceProtocol == "http")
		service.Target = resolver.target()
		if service.Target == "" {
			service.Ready = false
			if service.Registered {
				service.Failure = "runtime.target_unavailable"
			}
		}
	}
	snapshot.ObservedAt = time.Now().UTC()
	key, err := runtimeKey(project.Root, state)
	if err != nil {
		return snapshot, err
	}
	if !runtimeAvailable(ctx, key) {
		for index := range snapshot.Services {
			service := &snapshot.Services[index]
			if service.Registered {
				service.Failure = "runtime.manager_unavailable"
			}
			service.Registered, service.Routable, service.Ready = false, false, false
			service.Observation = nil
		}
	}
	return snapshot, nil
}

func readProjectServicesSnapshot(ctx context.Context, project projectConfiguration, state string) (clientruntime.Snapshot, error) {
	snapshot, err := readAppSnapshot(ctx, project, state)
	if err != nil {
		return snapshot, err
	}
	hasTCPService := false
	for name := range project.Config.Services {
		effective, err := project.EffectiveService(name)
		if err != nil {
			return snapshot, err
		}
		if config.ServiceProtocol(effective.Publish) != "http" {
			hasTCPService = true
			break
		}
	}
	if !hasTCPService {
		return snapshot, nil
	}
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		return snapshot, nil
	}
	database, err := clientstate.Open(ctx, state)
	if err != nil {
		return snapshot, err
	}
	defer database.Close()
	tunnels, err := database.SnapshotProject(ctx, project.Root)
	if err != nil {
		return snapshot, err
	}
	return mergeTCPServices(snapshot, project, tunnels.Tunnels), nil
}

func mergeTCPServices(snapshot clientruntime.Snapshot, project projectConfiguration, tunnels []clientstate.TunnelInfo) clientruntime.Snapshot {
	for name := range project.Config.Services {
		effective, _ := project.EffectiveService(name)
		protocol := config.ServiceProtocol(effective.Publish)
		if protocol == "http" {
			continue
		}
		service := clientruntime.Service{Name: name, Directory: project.RelativeServiceDirectories[name], ServiceProtocol: protocol}
		if effective.Publish != nil && effective.Publish.Target != nil {
			service.Target = string(*effective.Publish.Target)
		}
		var selected *clientstate.TunnelInfo
		for index := range tunnels {
			tunnel := &tunnels[index]
			if tunnel.Service != name || string(tunnel.ServiceProtocol) != protocol {
				continue
			}
			if selected == nil || (selected.State != clientstate.TunnelStateReady && tunnel.State == clientstate.TunnelStateReady) ||
				(selected.State == tunnel.State && tunnel.StartedAt.After(selected.StartedAt)) {
				selected = tunnel
			}
		}
		if selected != nil {
			service.TunnelID = selected.ID
			service.Registered = selected.State != clientstate.TunnelStateStale && selected.State != clientstate.TunnelStateDraining
			service.Routable = selected.State == clientstate.TunnelStateReady
			service.PublicURL, service.Target = selected.PublicURL, selected.Target
			service.PublishRunNumber = selected.PublishRunNumber
		}
		found := false
		for index := range snapshot.Services {
			if snapshot.Services[index].Name != name {
				continue
			}
			found = true
			if !snapshot.Services[index].Registered && selected != nil {
				snapshot.Services[index] = service
			}
			break
		}
		if !found {
			snapshot.Services = append(snapshot.Services, service)
		}
	}
	slices.SortFunc(snapshot.Services, func(a, b clientruntime.Service) int { return cmp.Compare(a.Name, b.Name) })
	return snapshot
}

func appServiceBlocks(snapshot clientruntime.Snapshot) []clioutput.Block {
	blocks := make([]clioutput.Block, 0, len(snapshot.Services))
	for _, service := range snapshot.Services {
		state := "not registered"
		if service.ServiceProtocol != "" {
			state = "not publishing"
			if service.Registered {
				state = "publishing"
			}
		}
		if service.Registered && service.ServiceProtocol == "" {
			state = "registered"
		}
		if service.Routable {
			state = "routable"
		}
		if service.Ready {
			state = "ready"
		}
		fields := []clioutput.Field{{Label: "service", Value: service.Name}, {Label: "directory", Value: service.Directory}}
		if service.ServiceProtocol != "" {
			fields = append(fields, clioutput.Field{Label: "protocol", Value: service.ServiceProtocol})
		}
		if service.Project != "" {
			fields = append(fields, clioutput.Field{Label: "project", Value: service.Project})
		}
		if service.PublicURL != "" {
			fields = append(fields, clioutput.Field{Label: "public URL", Value: service.PublicURL})
		}
		if service.Target != "" {
			fields = append(fields, clioutput.Field{Label: "target", Value: service.Target})
		}
		if service.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run number", Value: strconv.FormatUint(service.PublishRunNumber, 10)})
		}
		if service.ProvisioningStage != "" {
			fields = append(fields, clioutput.Field{Label: "provisioning", Value: service.ProvisioningStage})
		}
		if service.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "recent failure", Value: service.Failure})
		}
		if service.Observation != nil {
			fields = append(fields, clioutput.Field{Label: "checked at", Value: service.Observation.CheckedAt.Format(time.RFC3339Nano)})
			if service.Observation.Status != 0 {
				fields = append(fields, clioutput.Field{Label: "HTTP status", Value: strconv.Itoa(service.Observation.Status)})
			}
			if service.Observation.Reason != "" {
				fields = append(fields, clioutput.Field{Label: "readiness", Value: service.Observation.Reason})
			}
		}
		blocks = append(blocks, clioutput.Section(service.Name+" "+state, clioutput.Fields(fields...)))
	}
	return blocks
}

func runAppObservation(ctx context.Context, flags cli, command string, output io.Writer) error {
	stateDir := flags.Wait.StateDir
	if command == "watch" {
		stateDir = flags.Watch.StateDir
	}
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return err
	}
	project, err := loadProjectConfiguration(ctx, flags, root)
	if err != nil {
		return err
	}
	if !project.Found() || len(project.Config.Services) == 0 {
		return failure.Wrap("observe services", failure.ProjectConfigMissing, errors.New("configured services are required"))
	}
	if canonical, err := filepath.EvalSymlinks(root); err == nil {
		root = canonical
	}
	if command == "watch" {
		return runAppWatch(ctx, project, root, flags.Watch, output)
	}
	return runAppWait(ctx, project, root, flags.Wait, output)
}

func runAppWait(ctx context.Context, project projectConfiguration, state string, flags waitCommand, output io.Writer) error {
	return runAppWaitWithProbe(ctx, project, state, flags, output, func(ctx context.Context, service clientruntime.Service) clientruntime.Observation {
		return clientruntime.Probe(ctx, service, nil)
	})
}

func runAppWaitWithProbe(ctx context.Context, project projectConfiguration, state string, flags waitCommand, output io.Writer, probe func(context.Context, clientruntime.Service) clientruntime.Observation, tcpProbes ...func(context.Context, clientruntime.Service, bool) error) error {
	if flags.Timeout <= 0 {
		return failure.Wrap("wait for apps", failure.InvalidCommand, errors.New("timeout must be positive"))
	}
	for _, name := range flags.Service {
		if _, found := project.Config.Services[name]; !found {
			return failure.Wrap("wait for service", failure.ServiceNotConfigured, errors.New("service is not configured"))
		}
	}
	ctx, cancel := context.WithTimeout(ctx, flags.Timeout)
	defer cancel()
	var latest clientruntime.Snapshot
	for attempt := 0; ; attempt++ {
		snapshot, err := readProjectServicesSnapshot(ctx, project, state)
		if err != nil {
			return err
		}
		if len(flags.Service) != 0 {
			snapshot.Services = slices.DeleteFunc(snapshot.Services, func(service clientruntime.Service) bool { return !slices.Contains(flags.Service, service.Name) })
		}
		var workers sync.WaitGroup
		for index := range snapshot.Services {
			service := &snapshot.Services[index]
			service.Ready = false
			if !service.Registered || !service.Routable {
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				if service.ServiceProtocol != "" && service.ServiceProtocol != "http" {
					if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
						service.Ready = probeRemoteTarget(ctx, project, service.Name)
					} else {
						passthrough := tcpVisitorTLSPassthrough(project, service.Name)
						probeTCP := func(ctx context.Context, service clientruntime.Service, passthrough bool) error {
							return clientruntime.ProbeTCP(ctx, service.PublicURL, service.ServiceProtocol, passthrough, nil)
						}
						if len(tcpProbes) != 0 {
							probeTCP = tcpProbes[0]
						}
						service.Ready = probeTCP(ctx, *service, passthrough) == nil
					}
					return
				}
				observation := probe(ctx, *service)
				service.Ready, service.Observation = observation.Ready, &observation
			}()
		}
		workers.Wait()
		// a successful response is valid only for the registration and publish run
		// that were still current after its headers arrived.
		current, err := readProjectServicesSnapshot(ctx, project, state)
		if err != nil {
			return err
		}
		ready := len(snapshot.Services) > 0
		for index := range snapshot.Services {
			service := &snapshot.Services[index]
			matched := false
			for _, now := range current.Services {
				if now.Name == service.Name && now.Registered && now.Routable && now.RegistrationID == service.RegistrationID && now.TunnelID == service.TunnelID && now.PublishRunNumber == service.PublishRunNumber && now.Target == service.Target {
					matched = true
					break
				}
			}
			service.Ready = service.Ready && matched
			if matched && (service.ServiceProtocol == "" || service.ServiceProtocol == "http") && service.Observation != nil {
				var client namedPublisherClient
				var err error
				if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
					client, err = selectedPublisherClient(ctx, project, 10*time.Second)
				} else {
					var key string
					key, err = runtimeKey(project.Root, state)
					if err == nil {
						client.endpoint, err = readRuntimeTCPEndpoint(key)
						client.http = publisherHTTPClient(10 * time.Second)
					}
				}
				if err != nil {
					service.Ready = false
				} else if err := client.request(ctx, http.MethodPost, "/v1/observe", "", service.Observation, nil); err != nil {
					service.Ready = false
				}
			}
			ready = ready && service.Ready
		}
		latest = snapshot
		if ready {
			return writeAppWait(output, flags.Output, latest, "ready")
		}
		if ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(clientruntime.RetryDelay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err := writeAppWait(output, flags.Output, latest, "timed out"); err != nil {
		return err
	}
	return failure.Wrap("wait for public readiness", failure.AppReadinessTimeout, ctx.Err())
}

func tcpVisitorTLSPassthrough(project projectConfiguration, name string) bool {
	service := project.Config.Services[name]
	return service.TCP != nil && service.TCP.VisitorTLS != nil && *service.TCP.VisitorTLS == "passthrough"
}

func writeAppWait(output io.Writer, mode string, snapshot clientruntime.Snapshot, state string) error {
	if mode == "json" {
		return json.NewEncoder(output).Encode(snapshot)
	}
	return writeHumanFrame(output, "tnl wait", state, "", appServiceBlocks(snapshot)...)
}

func runAppWatch(ctx context.Context, project projectConfiguration, state string, flags watchCommand, output io.Writer) error {
	if selection := project.Config.Publisher; selection != nil && selection.Type != "local" {
		return runRemoteAppWatch(ctx, project, flags, output)
	}
	hasTCP := len(project.Config.Services) != len(configuredRuntimeServices(project))
	var database *clientstate.Database
	if hasTCP {
		var err error
		database, err = clientstate.Open(ctx, state)
		if err != nil {
			return err
		}
		defer database.Close()
	}
	cursor := flags.After
	if cursor == "" {
		snapshot, err := readAppSnapshot(ctx, project, state)
		if err != nil {
			return err
		}
		if hasTCP {
			sequence, err := database.LatestTunnelEventCursor(ctx, project.Root)
			if err != nil {
				return err
			}
			tunnels, err := database.SnapshotProject(ctx, project.Root)
			if err != nil {
				return err
			}
			snapshot = mergeTCPServices(snapshot, project, tunnels.Tunnels)
			cursor = watchCursor(snapshot.Cursor, sequence, true)
		} else {
			cursor = snapshot.Cursor
		}
		snapshot.Cursor = cursor
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
	}
	appCursor, tunnelCursor, err := parseWatchCursor(cursor)
	if err != nil {
		return failure.Wrap("resume local events", failure.InvalidCommand, err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		snapshot, err := clientruntime.ReadSnapshot(project.Root, state)
		if err != nil {
			return err
		}
		events, err := clientruntime.EventsAfter(snapshot, appCursor)
		if err != nil {
			return failure.Wrap("resume local events", failure.AppCursorExpired, err)
		}
		for _, event := range events {
			appCursor = event.Cursor
			event.Cursor = watchCursor(appCursor, tunnelCursor, hasTCP)
			if err := writeAppWatchEvent(output, flags.Output, event); err != nil {
				return err
			}
		}
		if hasTCP {
			if ctx.Err() != nil {
				return nil
			}
			tunnelEvents, err := database.TunnelEventsAfter(ctx, project.Root, tunnelCursor)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return failure.Wrap("resume local events", failure.AppCursorExpired, err)
			}
			for _, change := range tunnelEvents {
				tunnelCursor = change.Sequence
				effective, err := project.EffectiveService(change.Service)
				if err != nil || config.ServiceProtocol(effective.Publish) != string(change.ServiceProtocol) {
					continue
				}
				service := clientruntime.Service{
					Name: change.Service, Directory: project.RelativeServiceDirectories[change.Service],
					ServiceProtocol: string(change.ServiceProtocol), TunnelID: change.TunnelID, Target: change.Target,
					PublishRunNumber: change.PublishRunNumber,
					Registered:       change.State != clientstate.TunnelStateStopped && change.State != clientstate.TunnelStateFailed && change.State != clientstate.TunnelStateDraining,
					Routable:         change.State == clientstate.TunnelStateReady,
				}
				if change.Hostname != "" && change.PublicPort != 0 {
					service.PublicURL = net.JoinHostPort(change.Hostname, strconv.Itoa(int(change.PublicPort)))
				}
				kind := "service." + string(change.State)
				if change.State == clientstate.TunnelStateReady {
					kind = "service.publication"
				}
				event := clientruntime.Event{Cursor: watchCursor(appCursor, tunnelCursor, true), Type: kind, At: change.At, Service: &service}
				if err := writeAppWatchEvent(output, flags.Output, event); err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func watchCursor(app string, database uint64, hasTCP bool) string {
	if hasTCP {
		return app + ":" + strconv.FormatUint(database, 10)
	}
	return app
}

func parseWatchCursor(cursor string) (string, uint64, error) {
	app, database, combined := strings.Cut(cursor, ":")
	if _, err := clientruntime.ParseCursor(app); err != nil {
		return "", 0, err
	}
	if !combined {
		return app, 0, nil
	}
	sequence, err := clientruntime.ParseCursor(database)
	if err != nil {
		return "", 0, err
	}
	return app, sequence, nil
}

func writeAppWatchEvent(output io.Writer, mode string, event clientruntime.Event) error {
	if mode == "ndjson" {
		return json.NewEncoder(output).Encode(event)
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "cursor", Value: event.Cursor})}
	if event.Service != nil {
		blocks = append(blocks, appServiceBlocks(clientruntime.Snapshot{Services: []clientruntime.Service{*event.Service}})...)
	}
	if event.Snapshot != nil {
		blocks = append(blocks, appServiceBlocks(*event.Snapshot)...)
	}
	return writeHumanFrame(output, "tnl watch", event.Type, "", blocks...)
}
