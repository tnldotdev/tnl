package main

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/tcptarget"
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
	snapshot.ObservedAt = time.Now().UTC()
	socket, err := runtimeSocket(project.Root, state)
	if err != nil {
		return snapshot, err
	}
	if !runtimeAvailable(ctx, socket) {
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
	if len(project.Config.Services) == len(configuredRuntimeServices(project)) {
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
		index := slices.IndexFunc(snapshot.Services, func(service clientruntime.Service) bool { return service.Name == name })
		if index >= 0 && snapshot.Services[index].RegistrationID != "" {
			continue
		}
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
		if index >= 0 {
			snapshot.Services[index] = service
		} else {
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
	if command == "wait" && (!project.Found() || len(project.Config.Services) == 0) {
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

func runAppWaitWithProbe(ctx context.Context, project projectConfiguration, state string, flags waitCommand, output io.Writer, probe func(context.Context, clientruntime.Service) clientruntime.Observation) error {
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
					service.Ready = probeTCPTarget(ctx, service.Target)
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
				if now.Name == service.Name && now.Registered && now.Routable && now.RegistrationID == service.RegistrationID && now.TunnelID == service.TunnelID && now.PublishRunNumber == service.PublishRunNumber {
					matched = true
					break
				}
			}
			service.Ready = service.Ready && matched
			if matched && (service.ServiceProtocol == "" || service.ServiceProtocol == "http") && service.Observation != nil {
				data, err := json.Marshal(service.Observation)
				if err != nil {
					return err
				}
				socket, err := runtimeSocket(project.Root, state)
				if err != nil {
					return err
				}
				request, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/observe", bytes.NewReader(data))
				if err != nil {
					return err
				}
				request.Header.Set("Content-Type", "application/json")
				response, err := runtimeHTTP(socket).Do(request)
				if err == nil {
					response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						service.Ready = false
					}
				} else {
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

func probeTCPTarget(ctx context.Context, target string) bool {
	if _, err := tcptarget.Host(target); err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", target)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

func writeAppWait(output io.Writer, mode string, snapshot clientruntime.Snapshot, state string) error {
	if mode == "json" {
		return json.NewEncoder(output).Encode(snapshot)
	}
	return writeHumanFrame(output, "tnl wait", state, "", appServiceBlocks(snapshot)...)
}

func runAppWatch(ctx context.Context, project projectConfiguration, state string, flags watchCommand, output io.Writer) error {
	cursor := flags.After
	if cursor == "" {
		snapshot, err := readAppSnapshot(ctx, project, state)
		if err != nil {
			return err
		}
		database, err := clientstate.Open(ctx, state)
		if err != nil {
			return err
		}
		current, snapshotErr := database.SnapshotProject(ctx, project.Root)
		closeErr := database.Close()
		if snapshotErr != nil || closeErr != nil {
			return errors.Join(snapshotErr, closeErr)
		}
		snapshot = mergeTCPServices(snapshot, project, current.Tunnels)
		for _, tunnel := range current.Tunnels {
			if tunnel.Command == clientstate.TunnelCommandPublish && tunnel.Service == "" {
				snapshot.Tunnels = append(snapshot.Tunnels, tunnel)
			}
		}
		cursor = snapshot.Cursor
		if flags.Output == "ndjson" {
			if err := json.NewEncoder(output).Encode(struct {
				Type     string                 `json:"type"`
				Snapshot clientruntime.Snapshot `json:"snapshot"`
			}{"snapshot", snapshot}); err != nil {
				return err
			}
		} else {
			blocks := appServiceBlocks(snapshot)
			for _, tunnel := range snapshot.Tunnels {
				blocks = append(blocks, clioutput.Section("direct "+string(tunnel.State), clioutput.Fields(
					clioutput.Field{Label: "tunnel", Value: tunnel.ID}, clioutput.Field{Label: "target", Value: tunnel.Target},
					clioutput.Field{Label: "public URL", Value: tunnel.PublicURL})))
			}
			if err := writeHumanFrame(output, "tnl watch", "snapshot", "cursor "+cursor, blocks...); err != nil {
				return err
			}
		}
	}
	if _, err := clientruntime.ParseCursor(cursor); err != nil {
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
		events, err := clientruntime.EventsAfter(snapshot, cursor)
		if err != nil {
			return failure.Wrap("resume local events", failure.AppCursorExpired, err)
		}
		for _, event := range events {
			cursor = event.Cursor
			if err := writeAppWatchEvent(output, flags.Output, event); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func writeAppWatchEvent(output io.Writer, mode string, event clientruntime.Event) error {
	if mode == "ndjson" {
		return json.NewEncoder(output).Encode(event)
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "cursor", Value: event.Cursor})}
	if event.Service != nil {
		blocks = append(blocks, appServiceBlocks(clientruntime.Snapshot{Services: []clientruntime.Service{*event.Service}})...)
	}
	if event.Tunnel != nil {
		fields := []clioutput.Field{{Label: "tunnel", Value: event.Tunnel.ID}, {Label: "target", Value: event.Tunnel.Target}}
		if event.Tunnel.PublicURL != "" {
			fields = append(fields, clioutput.Field{Label: "public URL", Value: event.Tunnel.PublicURL})
		}
		if event.Tunnel.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run number", Value: strconv.FormatUint(event.Tunnel.PublishRunNumber, 10)})
		}
		blocks = append(blocks, clioutput.Fields(fields...))
	}
	if event.Publication != nil {
		fields := []clioutput.Field{{Label: "progress", Value: event.Publication.Type}}
		if event.Publication.Hostname != "" {
			fields = append(fields, clioutput.Field{Label: "hostname", Value: event.Publication.Hostname})
		}
		if event.Publication.PublicURL != "" {
			fields = append(fields, clioutput.Field{Label: "public URL", Value: event.Publication.PublicURL})
		}
		if event.Publication.Transport != "" {
			fields = append(fields, clioutput.Field{Label: "transport", Value: event.Publication.Transport})
		}
		if event.Publication.PolicyDenials != 0 {
			fields = append(fields, clioutput.Field{Label: "policy denials", Value: strconv.FormatUint(event.Publication.PolicyDenials, 10)})
		}
		blocks = append(blocks, clioutput.Fields(fields...))
	}
	if event.Snapshot != nil {
		blocks = append(blocks, appServiceBlocks(*event.Snapshot)...)
	}
	return writeHumanFrame(output, "tnl watch", event.Type, "", blocks...)
}
