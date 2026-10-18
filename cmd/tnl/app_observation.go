package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

type waitCommand struct {
	StateDir string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Service  []string      `name:"service" help:"Check this service; repeat to select several. Defaults to every configured service."`
	Timeout  time.Duration `name:"timeout" default:"2m" help:"Time to wait for fresh public readiness checks."`
	Output   string        `name:"output" enum:"human,json" default:"human"`
}
type watchCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	After    string `name:"after" help:"Resume exclusively after this opaque local event cursor."`
	Output   string `name:"output" enum:"human,ndjson" default:"human"`
}

func readAppSnapshotFrom(ctx context.Context, project projectConfiguration, state *clientstate.Database) (clientruntime.Snapshot, error) {
	snapshot, err := clientruntime.ReadSnapshotFrom(ctx, state, project.Root)
	if err != nil {
		return snapshot, err
	}
	configured := configuredRuntimeServices(project)
	for index := range configured {
		for _, saved := range snapshot.Services {
			if saved.Name != configured[index].Name {
				continue
			}
			definition := configured[index]
			configured[index] = saved
			configured[index].Directory, configured[index].Readiness, configured[index].ServiceProtocol = definition.Directory, definition.Readiness, definition.ServiceProtocol
			if saved.Readiness != definition.Readiness {
				configured[index].Ready, configured[index].Observation = false, nil
			}
			for _, publication := range snapshot.Publications {
				if publication.Service == saved.Name && publication.Target == saved.Target && publication.State == clientstate.TunnelStateStale {
					configured[index].Registered, configured[index].Routable, configured[index].Ready = false, false, false
					configured[index].Observation, configured[index].Failure = nil, "runtime.manager_unavailable"
				}
			}
			break
		}
	}
	snapshot.Services = configured
	return snapshot, nil
}

func appServiceBlocks(snapshot clientruntime.Snapshot) []clioutput.Block {
	blocks := make([]clioutput.Block, 0, len(snapshot.Services))
	for _, service := range snapshot.Services {
		state := "not registered"
		if service.Registered {
			state = "registered"
		}
		if service.Routable {
			state = "routable"
		}
		if service.Ready {
			state = "ready"
		}
		fields := []clioutput.Field{{Label: "service", Value: service.Name}, {Label: "directory", Value: service.Directory}}
		for _, value := range []clioutput.Field{{Label: "protocol", Value: service.ServiceProtocol}, {Label: "project", Value: service.Project}, {Label: "public URL", Value: service.PublicURL}, {Label: "target", Value: service.Target}, {Label: "provisioning", Value: service.ProvisioningStage}, {Label: "recent failure", Value: service.Failure}} {
			if value.Value != "" {
				fields = append(fields, value)
			}
		}
		if service.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run number", Value: strconv.FormatUint(service.PublishRunNumber, 10)})
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
		blocks = append(blocks, clioutput.Section("local "+service.Name+" "+state, clioutput.Fields(fields...)))
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
	if command == "watch" {
		return runAppWatch(ctx, project, root, flags.Watch, output)
	}
	return runAppWait(ctx, project, root, flags.Wait, output)
}

func runAppWait(ctx context.Context, project projectConfiguration, root string, flags waitCommand, output io.Writer) error {
	if flags.Timeout <= 0 {
		return failure.Wrap("wait for apps", failure.InvalidCommand, errors.New("timeout must be positive"))
	}
	for _, name := range flags.Service {
		if _, found := project.Config.Services[name]; !found {
			return failure.Wrap("wait for service", failure.ServiceNotConfigured, errors.New("service is not configured"))
		}
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	path, err := privateprotocol.DescriptorPath(state.Root(), project.Root)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, flags.Timeout)
	defer cancel()
	var latest clientruntime.Snapshot
	checkSource := "local publisher process unavailable"
	for attempt := 0; ; attempt++ {
		snapshot, err := readAppSnapshotFrom(context.WithoutCancel(ctx), project, state)
		if err != nil {
			return err
		}
		checked := false
		if endpoint, err := privateprotocol.ReadEndpoint(path); err == nil {
			request := privateprotocol.Check{}
			if len(flags.Service) != 0 {
				request.Services = &flags.Service
			}
			var current clientruntime.Snapshot
			if err := privateprotocol.Call(ctx, endpoint, "POST", "/v1/check", request, &current); err == nil {
				snapshot, checked = current, true
				checkSource = "selected local publisher process (fresh public-path check)"
			} else {
				checkSource = "selected local publisher process unavailable"
			}
		}
		snapshot.Services = slices.DeleteFunc(snapshot.Services, func(s clientruntime.Service) bool {
			if len(flags.Service) != 0 {
				return !slices.Contains(flags.Service, s.Name)
			}
			_, configured := project.Config.Services[s.Name]
			return !configured
		})
		want := len(flags.Service)
		if want == 0 {
			want = len(project.Config.Services)
		}
		ready := checked && len(snapshot.Services) == want
		for index := range snapshot.Services {
			if !checked {
				snapshot.Services[index].Ready = false
				snapshot.Services[index].Observation = nil
				snapshot.Services[index].Failure = "runtime.manager_unavailable"
			}
			ready = ready && snapshot.Services[index].Registered && snapshot.Services[index].Routable && snapshot.Services[index].Ready
		}
		latest = snapshot
		if ready {
			return writeAppWait(output, flags.Output, latest, "ready", checkSource)
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
	if err := writeAppWait(output, flags.Output, latest, "timed out", checkSource); err != nil {
		return err
	}
	return failure.Wrap("wait for public readiness", failure.AppReadinessTimeout, ctx.Err())
}

func writeAppWait(output io.Writer, mode string, snapshot clientruntime.Snapshot, state, checkedBy string) error {
	if mode == "json" {
		return json.NewEncoder(output).Encode(struct {
			clientruntime.Snapshot
			State     string `json:"state"`
			CheckedBy string `json:"checked_by"`
		}{snapshot, state, checkedBy})
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "checked by", Value: checkedBy})}
	return writeHumanFrame(output, "tnl wait", state, "", append(blocks, appServiceBlocks(snapshot)...)...)
}

func runAppWatch(ctx context.Context, project projectConfiguration, root string, flags watchCommand, output io.Writer) error {
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	cursor := flags.After
	if cursor == "" {
		snapshot, err := readAppSnapshotFrom(ctx, project, state)
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
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		events, err := clientruntime.EventsAfterFrom(ctx, state, project.Root, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return failure.Wrap("resume local events", failure.AppCursorExpired, err)
		}
		for _, event := range events {
			if err := writeAppWatchEvent(output, flags.Output, event); err != nil {
				return err
			}
			cursor = event.Cursor
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
	if event.Snapshot != nil {
		blocks = append(blocks, appServiceBlocks(*event.Snapshot)...)
	}
	if event.Publication != nil {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "tunnel", Value: event.Publication.ID}, clioutput.Field{Label: "state", Value: string(event.Publication.State)}, clioutput.Field{Label: "public URL", Value: event.Publication.PublicURL}))
	}
	return writeHumanFrame(output, "tnl watch", event.Type, "", blocks...)
}
