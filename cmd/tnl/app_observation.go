package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
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

func readAppSnapshotFrom(ctx context.Context, project projectConfiguration, state *clientstate.Database) (publisherapp.Snapshot, error) {
	snapshot, err := publisherapp.ReadSnapshotFrom(ctx, state, project.Root)
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
	checkAppSnapshotOwner(ctx, state, &snapshot)
	return snapshot, nil
}

// a private worker has no public tunnel heartbeat. verify the owner before
// presenting durable readiness as current, including status --all and watch.
func checkAppSnapshotOwner(ctx context.Context, state *clientstate.Database, snapshot *publisherapp.Snapshot) {
	if !slices.ContainsFunc(snapshot.Services, func(s publisherapp.Service) bool { return s.Registered }) {
		return
	}
	probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	path, err := publisherprotocol.DescriptorPath(state.Root(), snapshot.Project)
	if err == nil {
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil && local.Available(probe, endpoint) {
			return
		}
	}
	for index := range snapshot.Services {
		service := &snapshot.Services[index]
		if service.Registered {
			service.Registered, service.Routable, service.Ready = false, false, false
			service.Observation, service.Failure = nil, "runtime.manager_unavailable"
		}
	}
}

type observationRow struct {
	name, state, address, lastError string
}

func (r observationRow) blocks() []clioutput.Block {
	line := r.name + ": " + r.state
	if r.address != "" {
		line += "  " + r.address
	}
	blocks := []clioutput.Block{clioutput.Line(line)}
	if r.lastError != "" {
		blocks = append(blocks, clioutput.Text("Last error: "+r.lastError))
	}
	return blocks
}

func observationName(name string) string {
	if name == "" || opaqueid.Valid(name, opaqueid.InvocationPrefix) {
		return "publication"
	}
	return name
}

func observationError(code string) string {
	if reason, ok := failure.DefinitionFor(failure.Reason(code)); ok {
		return reason.Message
	}
	switch code {
	case "":
		return ""
	case "runtime.manager_unavailable":
		return "the local tnl process is unavailable"
	case "runtime.manager_restarted":
		return "the local tnl process restarted"
	case "runtime.registration_stale":
		return "the app registration is stale"
	case "runtime.probe_failed":
		return "the readiness check could not complete"
	case "runtime.probe_rejected":
		return "the readiness check did not get a successful response"
	case "runtime.target_changed":
		return "the readiness check could not confirm the current target"
	case "runtime.publication_failed":
		return "tnl could not publish the service"
	case "runtime.publication_cleanup_failed":
		return "tnl could not finish cleaning up the publication"
	case "runtime.provisioning_stalled":
		return "publication setup has stalled"
	case "runtime.preparation_failed":
		return "tnl could not prepare the service"
	default:
		return "no further details available"
	}
}

func appServiceRow(s publisherapp.Service) observationRow {
	r := observationRow{name: observationName(s.Name), address: s.PublicURL, lastError: observationError(s.Failure)}
	switch {
	case s.Failure == "runtime.manager_unavailable":
		r.state = "readiness not confirmed"
	case !s.Registered:
		r.state = "not registered"
	case !s.Routable:
		r.state = "registered, waiting for a connection"
		if s.PublicURL != "" {
			r.state = "public readiness not confirmed"
		}
		if s.ProvisioningStage != "" {
			r.state = "provisioning: " + strings.ReplaceAll(s.ProvisioningStage, "_", " ")
		}
	case s.Ready:
		r.state = "ready"
		if s.PublicURL == "" {
			r.state = "ready (target checked; no public URL)"
		}
	default:
		r.state = "public readiness not confirmed"
		if s.PublicURL == "" {
			r.state = "target readiness not confirmed"
		}
		if o := s.Observation; o != nil && !o.Ready {
			if o.Reason != "runtime.target_changed" {
				r.state = "readiness check failed"
				if o.Status != 0 {
					r.state += " (HTTP " + strconv.Itoa(o.Status) + ")"
				}
			}
			if r.lastError == "" {
				r.lastError = observationError(o.Reason)
			}
		}
	}
	return r
}

func publicationRow(t clientstate.TunnelInfo) observationRow {
	r := observationRow{name: observationName(t.Service), state: string(t.State), address: t.PublicURL, lastError: observationError(t.Failure)}
	if r.name != "publication" {
		r.name += " publication"
	}
	if t.State == clientstate.TunnelStateReady {
		// the tunnel is routable; it has no app readiness check of its own.
		r.state = "routable"
	}
	return r
}

type snapshotObservation struct {
	key      string
	row      observationRow
	canWait  bool
	lastSeen time.Time
}

// show an app and its current tunnel once. a stale lease or a draining tunnel
// takes precedence over a saved app check; other publications stand alone.
func snapshotObservations(services []publisherapp.Service, tunnels []clientstate.TunnelInfo) []snapshotObservation {
	var rows []snapshotObservation
	unmatched := make(map[string]clientstate.TunnelInfo, len(tunnels))
	for _, t := range tunnels {
		unmatched[t.ID] = t
	}
	for _, s := range services {
		entry := snapshotObservation{key: s.Name, row: appServiceRow(s), canWait: s.Registered && !s.Ready}
		if t, linked := unmatched[s.TunnelID]; linked && s.TunnelID != "" {
			if t.State == clientstate.TunnelStateStale || t.State == clientstate.TunnelStateDraining {
				entry.row.state, entry.canWait, entry.lastSeen = string(t.State), false, t.HeartbeatAt
			}
			delete(unmatched, s.TunnelID)
		}
		rows = append(rows, entry)
	}
	for _, t := range tunnels {
		if _, show := unmatched[t.ID]; show {
			rows = append(rows, snapshotObservation{key: "publication:" + t.ID, row: publicationRow(t), lastSeen: t.HeartbeatAt})
		}
	}
	return rows
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
	if config.SelectedDeployment(project.Config) != "local" {
		return failure.Wrap("wait for local service", failure.AppRemoteService, errors.New("the selected deployment is remote"))
	}
	for _, name := range flags.Service {
		_, found := project.Config.Services[name]
		if !found {
			return failure.Wrap("wait for service", failure.ServiceNotConfigured, errors.New("service is not configured"))
		}
	}
	if len(flags.Service) == 0 {
		for _, service := range configuredRuntimeServices(project) {
			flags.Service = append(flags.Service, service.Name)
		}
	}
	if len(flags.Service) == 0 {
		return failure.Wrap("wait for local services", failure.AppRemoteService, errors.New("no local services are configured"))
	}
	slices.Sort(flags.Service)
	flags.Service = slices.Compact(flags.Service)
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	path, err := publisherprotocol.DescriptorPath(state.Root(), project.Root)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, flags.Timeout)
	defer cancel()
	var latest publisherapp.Snapshot
	checkSource := "local publisher process unavailable"
	for attempt := 0; ; attempt++ {
		snapshot, err := readAppSnapshotFrom(context.WithoutCancel(ctx), project, state)
		if err != nil {
			return err
		}
		checked := false
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil {
			request := publisherprotocol.Check{}
			if len(flags.Service) != 0 {
				request.Services = &flags.Service
			}
			var current publisherapp.Snapshot
			if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/check", request, &current); err == nil {
				snapshot, checked = current, true
				checkSource = "selected local publisher process (fresh public-path check)"
			} else {
				checkSource = "selected local publisher process unavailable"
			}
		}
		snapshot.Services = slices.DeleteFunc(snapshot.Services, func(s publisherapp.Service) bool {
			if len(flags.Service) != 0 {
				return !slices.Contains(flags.Service, s.Name)
			}
			_, configured := project.Config.Services[s.Name]
			return !configured
		})
		want := len(flags.Service)
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
		timer := time.NewTimer(publisherapp.RetryDelay(attempt))
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

func writeAppWait(output io.Writer, mode string, snapshot publisherapp.Snapshot, state, checkedBy string) error {
	if mode == "json" {
		return json.NewEncoder(output).Encode(struct {
			publisherapp.Snapshot
			State     string `json:"state"`
			CheckedBy string `json:"checked_by"`
		}{snapshot, state, checkedBy})
	}
	var blocks []clioutput.Block
	if state != "ready" {
		blocks = append(blocks, clioutput.Text("Timed out waiting for readiness."))
	}
	for _, s := range snapshot.Services {
		blocks = append(blocks, appServiceRow(s).blocks()...)
	}
	return writeResult(output, blocks...)
}

func runAppWatch(ctx context.Context, project projectConfiguration, root string, flags watchCommand, output io.Writer) (result error) {
	ctx, finish := observability.ClientOperation(ctx, "client.watch.startup")
	defer func() { finish(result) }()
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	cursor := flags.After
	watch := make(humanWatch)
	if cursor == "" {
		snapshot, err := readAppSnapshotFrom(ctx, project, state)
		if err != nil {
			return err
		}
		cursor = snapshot.Cursor
		if flags.Output == "ndjson" {
			if err := json.NewEncoder(output).Encode(struct {
				Type     string                `json:"type"`
				Snapshot publisherapp.Snapshot `json:"snapshot"`
			}{"snapshot", snapshot}); err != nil {
				return err
			}
		} else {
			var blocks []clioutput.Block
			for _, entry := range snapshotObservations(snapshot.Services, snapshot.Publications) {
				watch[entry.key] = entry.row
				blocks = append(blocks, entry.row.blocks()...)
			}
			if len(blocks) == 0 {
				blocks = append(blocks, clioutput.Text("No local services to watch."))
			}
			if err := writeResult(output, blocks...); err != nil {
				return err
			}
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	finish(nil)
	ctx = observability.Independent(ctx)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		poll, finishPoll := observability.ClientOperation(ctx, "client.watch.poll")
		events, err := publisherapp.EventsAfterFrom(poll, state, project.Root, cursor)
		finishPoll(err)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return failure.Wrap("resume local events", failure.AppCursorExpired, err)
		}
		for _, event := range events {
			if err := watch.writeEvent(output, flags.Output, event); err != nil {
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

type humanWatch map[string]observationRow

func (w humanWatch) writeEvent(output io.Writer, mode string, event publisherapp.Event) error {
	if mode == "ndjson" {
		return json.NewEncoder(output).Encode(event)
	}
	var row observationRow
	var key string
	var terminal bool
	switch {
	case event.Service != nil:
		s := *event.Service
		key, row.name = s.Name, observationName(s.Name)
		switch event.Type {
		case "service.readiness", "service.provisioning", "service.publication":
			row = appServiceRow(s)
		case "service.bound":
			row.state = "publication attached"
		case "service.failed", "service.warning":
			row.state = strings.TrimPrefix(event.Type, "service.")
			row.lastError = observationError(s.Failure)
		case "service.stopped":
			row.state = "stopped"
			row.lastError = observationError(s.Failure)
		case "service.replacing":
			row.state = "replacing registration"
		default:
			row.state = strings.TrimPrefix(event.Type, "service.")
		}
		terminal = event.Type == "service.unregistered" || event.Type == "service.stopped"
	case event.Publication != nil:
		t := *event.Publication
		key, row = "publication:"+t.ID, publicationRow(t)
		terminal = t.State == clientstate.TunnelStateStopped || t.State == clientstate.TunnelStateFailed
	default:
		// a process event carries a full journal snapshot, including services
		// that did not change. report the operation that produced it.
		switch event.Type {
		case "runtime.started", "runtime.stopped", "runtime.restarted":
			clear(w)
			return writeResult(output, clioutput.Text("Local tnl process "+strings.TrimPrefix(event.Type, "runtime.")+"."))
		case "runtime.configured", "service.configured":
			return writeResult(output, clioutput.Text("Service configuration updated."))
		default:
			return writeResult(output, clioutput.Text(strings.ReplaceAll(event.Type, ".", " ")))
		}
	}
	previous := w[key]
	if previous == row {
		return nil
	}
	if terminal {
		delete(w, key)
	} else {
		w[key] = row
	}
	if row.lastError == previous.lastError {
		row.lastError = ""
	}
	return writeResult(output, row.blocks()...)
}

func (a *commandApp) newWaitCommand() *cobra.Command {
	f := a.flags
	cWait := &cobra.Command{
		Use: "wait", Short: "Wait until configured services are ready.", GroupID: "observe",
		Long: "Ask this worktree's running tnl process to check readiness. Wait for all local services, or repeat --service to select which ones must be ready.",
	}
	a.leaf(cWait, &f.Wait, func(call commandCall) error {
		return runAppObservation(call.ctx, *f, "wait", a.out)
	})
	return cWait
}

func (a *commandApp) newWatchCommand() *cobra.Command {
	f := a.flags
	cWatch := &cobra.Command{
		Use: "watch", Short: "Follow this worktree's service events.", GroupID: "observe",
		Long: "Follow local publication events as they happen. To resume, use the last event cursor from the same worktree and client state directory.",
	}
	a.leaf(cWatch, &f.Watch, func(call commandCall) error {
		return runAppObservation(call.ctx, *f, "watch", a.out)
	})
	return cWatch
}
