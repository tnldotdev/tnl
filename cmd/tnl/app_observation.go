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
	Timeout  time.Duration `name:"timeout" default:"2m" help:"Time to wait for fresh readiness checks."`
	Output   string        `name:"output" enum:"human,json" default:"human"`
}
type watchCommand struct {
	StateDir string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Service  string        `name:"service" help:"Follow only this configured service."`
	After    string        `name:"after" help:"Resume exclusively after this opaque local event cursor."`
	Count    int           `name:"count" help:"Exit successfully after this many matching events. The initial snapshot does not count."`
	Timeout  time.Duration `name:"timeout" help:"Exit with a timeout error after this duration if still watching."`
	Output   string        `name:"output" enum:"human,ndjson" default:"human"`
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
				if saved.TunnelID != "" && publication.ID == saved.TunnelID && publication.State == clientstate.TunnelStateStale {
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
	key     string
	service *publisherapp.Service
	tunnel  *clientstate.TunnelInfo
}

// pair an app with its own tunnel, leaving other publications independent.
func snapshotObservations(services []publisherapp.Service, tunnels []clientstate.TunnelInfo) []snapshotObservation {
	var rows []snapshotObservation
	unmatched := make(map[string]*clientstate.TunnelInfo, len(tunnels))
	for i := range tunnels {
		unmatched[tunnels[i].ID] = &tunnels[i]
	}
	for i := range services {
		s := &services[i]
		entry := snapshotObservation{key: s.Name, service: s}
		if s.TunnelID != "" {
			entry.tunnel = unmatched[s.TunnelID]
			delete(unmatched, s.TunnelID)
		}
		rows = append(rows, entry)
	}
	for _, t := range tunnels {
		if tunnel, show := unmatched[t.ID]; show {
			rows = append(rows, snapshotObservation{key: "publication:" + t.ID, tunnel: tunnel})
		}
	}
	return rows
}

func (entry snapshotObservation) watchRow() observationRow {
	if entry.service == nil {
		return publicationRow(*entry.tunnel)
	}
	row := appServiceRow(*entry.service)
	if t := entry.tunnel; t != nil && (t.State == clientstate.TunnelStateStale || t.State == clientstate.TunnelStateDraining) {
		row.state = string(t.State)
	}
	return row
}

func runAppObservation(ctx context.Context, flags cli, command string, output, diagnostics io.Writer) error {
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
	return runAppWait(ctx, project, root, flags.Wait, output, diagnostics)
}

func runAppWait(ctx context.Context, project projectConfiguration, root string, flags waitCommand, output, diagnostics io.Writer) error {
	if flags.Timeout <= 0 {
		return failure.Wrap("wait for apps", failure.InvalidCommand, errors.New("timeout must be positive"))
	}
	if config.SelectedDeployment(project.Config) != "local" {
		return failure.Wrap("wait for local service", failure.AppRemoteService, errors.New("the selected deployment is remote"))
	}
	configured := configuredRuntimeServices(project)
	for _, name := range flags.Service {
		if !slices.ContainsFunc(configured, func(s publisherapp.Service) bool { return s.Name == name }) {
			return unconfiguredService(name)
		}
	}
	selected := slices.DeleteFunc(configured, func(s publisherapp.Service) bool {
		return len(flags.Service) > 0 && !slices.Contains(flags.Service, s.Name)
	})
	if len(selected) == 0 {
		return failure.Wrap("wait for local services", failure.AppRemoteService, errors.New("no local services are configured"))
	}
	names := make([]string, 0, len(selected))
	for _, service := range selected {
		names = append(names, service.Name)
	}
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
	label := "Checking services"
	if len(names) == 1 {
		label = "Checking " + names[0]
	}
	stopProgress := clioutput.StartProgress(ctx, output, diagnostics, flags.Output != "json", label)
	defer stopProgress()
	latest := publisherapp.Snapshot{SchemaVersion: 1, Project: project.Root}
	checkSource := "local publisher process unavailable"
	latest.Services, _ = waitObservations(selected, latest.Services, time.Time{})
	for attempt := 0; ; attempt++ {
		var current publisherapp.Snapshot
		var checkStarted time.Time
		if endpoint, err := publisherprotocol.ReadEndpoint(path); err == nil {
			started := time.Now()
			if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &names}, &current); err == nil {
				checkStarted = started
			}
		}
		if ctx.Err() != nil {
			break
		}
		if checkStarted.IsZero() {
			current, err = readAppSnapshotFrom(ctx, project, state)
			if err != nil {
				if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
					break
				}
				return err
			}
		}
		current.Services, checkSource = waitObservations(selected, current.Services, checkStarted)
		current.Publications = slices.DeleteFunc(current.Publications, func(p clientstate.TunnelInfo) bool {
			return !slices.Contains(names, p.Service)
		})
		latest = current
		if !slices.ContainsFunc(latest.Services, func(s publisherapp.Service) bool { return !s.Ready }) {
			stopProgress()
			return writeAppWait(output, flags.Output, latest, "ready", checkSource)
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
	stopProgress()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return context.Cause(ctx)
	}
	if err := writeAppWait(output, flags.Output, latest, "timed out", checkSource); err != nil {
		return err
	}
	return failure.Wrap("wait for public readiness", failure.AppReadinessTimeout, ctx.Err())
}

func waitObservations(selected, current []publisherapp.Service, started time.Time) ([]publisherapp.Service, string) {
	byName := make(map[string]publisherapp.Service, len(current))
	for _, service := range current {
		byName[service.Name] = service
	}
	services := make([]publisherapp.Service, 0, len(selected))
	var public, target bool
	for _, definition := range selected {
		s, found := byName[definition.Name]
		if !found {
			s = definition
		}
		o := s.Observation
		if started.IsZero() {
			s.Ready, s.Observation, s.Failure = false, nil, "runtime.manager_unavailable"
		} else if !s.Registered || !s.Routable || s.Readiness != definition.Readiness || s.ServiceProtocol != definition.ServiceProtocol ||
			o == nil || o.CheckedAt.Before(started) || o.RegistrationID != s.RegistrationID || o.RunNumber != s.RunNumber || o.Readiness != s.Readiness {
			s.Ready, s.Observation = false, nil
		} else {
			s.Ready = s.Ready && o.Ready
			if s.PublicURL != "" {
				public = true
			} else {
				target = true
			}
		}
		services = append(services, s)
	}
	switch {
	case started.IsZero():
		return services, "local publisher process unavailable"
	case public && target:
		return services, "selected local publisher process (fresh public-path and target checks)"
	case public:
		return services, "selected local publisher process (fresh public-path check)"
	case target:
		return services, "selected local publisher process (fresh target check)"
	default:
		return services, "selected local publisher process (no fresh check result)"
	}
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

var errAppWatchDeadline = errors.New("watch deadline reached")

func appWatchEnd(ctx context.Context) error {
	if context.Cause(ctx) == errAppWatchDeadline {
		return failure.Wrap("follow local events", failure.AppWatchTimeout, context.DeadlineExceeded)
	}
	if failure.Only(context.Cause(ctx), context.Canceled) {
		return nil
	}
	return context.Cause(ctx)
}

func runAppWatch(ctx context.Context, project projectConfiguration, root string, flags watchCommand, output io.Writer) (result error) {
	ctx, finish := observability.ClientOperation(ctx, "client.watch.startup")
	defer func() { finish(result) }()
	if flags.Service != "" {
		if _, found := project.Config.Services[flags.Service]; !found {
			return unconfiguredService(flags.Service)
		}
	}
	if flags.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, flags.Timeout, errAppWatchDeadline)
		defer cancel()
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
			return appWatchEnd(ctx)
		}
		return err
	}
	defer state.Close()
	cursor := flags.After
	watch := make(humanWatch)
	if cursor == "" {
		snapshot, err := readAppSnapshotFrom(ctx, project, state)
		if err != nil {
			if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
				return appWatchEnd(ctx)
			}
			return err
		}
		if ctx.Err() != nil {
			return appWatchEnd(ctx)
		}
		cursor = snapshot.Cursor
		if flags.Service != "" {
			snapshot.Services = slices.DeleteFunc(snapshot.Services, func(s publisherapp.Service) bool { return s.Name != flags.Service })
			snapshot.Publications = slices.DeleteFunc(snapshot.Publications, func(p clientstate.TunnelInfo) bool { return p.Service != flags.Service })
		}
		if flags.Output == "ndjson" {
			if err := json.NewEncoder(output).Encode(struct {
				Type     string                `json:"type"`
				Snapshot publisherapp.Snapshot `json:"snapshot"`
			}{"snapshot", snapshot}); err != nil {
				return err
			}
		} else if err := watch.writeSnapshot(output, snapshot); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	finish(nil)
	ctx = observability.Independent(ctx)
	defer ticker.Stop()
	matched := 0
	for {
		if ctx.Err() != nil {
			return appWatchEnd(ctx)
		}
		poll, finishPoll := observability.ClientOperation(ctx, "client.watch.poll")
		events, err := publisherapp.EventsAfterFrom(poll, state, project.Root, cursor)
		finishPoll(err)
		if err != nil {
			if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
				return appWatchEnd(ctx)
			}
			if errors.Is(err, publisherapp.ErrCursorExpired) {
				return err
			}
			return failure.Wrap("read local events", failure.ClientStateUnavailable, err)
		}
		for _, event := range events {
			if ctx.Err() != nil {
				return appWatchEnd(ctx)
			}
			if watchMatches(flags.Service, event) {
				if err := watch.writeEvent(output, flags.Output, event, flags.Count > 0); err != nil {
					return err
				}
				if flags.Count > 0 {
					matched++
					if matched == flags.Count {
						return nil
					}
				}
			}
			cursor = event.Cursor
		}
		select {
		case <-ctx.Done():
			return appWatchEnd(ctx)
		case <-ticker.C:
		}
	}
}

func watchMatches(service string, event publisherapp.Event) bool {
	if service == "" {
		return true
	}
	// process snapshots may include the service even though it did not change.
	return event.Service != nil && event.Service.Name == service ||
		event.Publication != nil && event.Publication.Service == service
}

type humanWatch map[string]observationRow

func (w humanWatch) writeSnapshot(output io.Writer, snapshot publisherapp.Snapshot) error {
	var blocks []clioutput.Block
	for _, entry := range snapshotObservations(snapshot.Services, snapshot.Publications) {
		row := entry.watchRow()
		w[entry.key] = row
		blocks = append(blocks, row.blocks()...)
	}
	if len(blocks) == 0 {
		blocks = append(blocks, clioutput.Text("No local services to watch."))
	}
	return writeResult(output, blocks...)
}

func (w humanWatch) writeEvent(output io.Writer, mode string, event publisherapp.Event, counted bool) error {
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
	if !counted && previous == row {
		return nil
	}
	if terminal {
		delete(w, key)
	} else {
		w[key] = row
	}
	if !counted && row.lastError == previous.lastError {
		row.lastError = ""
	}
	return writeResult(output, row.blocks()...)
}

func (a *commandApp) newWaitCommand() *cobra.Command {
	f := a.flags
	cWait := &cobra.Command{
		Use: "wait [service...]", Short: "Wait until configured services are ready.", GroupID: "observe",
		Long:        "Ask this worktree's running tnl process to check readiness. Name the services that must be ready, or omit names to check all configured local services. Checks may verify only the local target.",
		Annotations: map[string]string{"cliflags:arg:service...": "Configured local service names."},
	}
	a.leaf(cWait, &f.Wait, func(call commandCall) error {
		return runAppObservation(call.ctx, *f, "wait", a.out, a.errOut)
	})
	parseWaitFlags := cWait.Args
	cWait.Args = func(cmd *cobra.Command, args []string) error {
		if err := parseWaitFlags(cmd, nil); err != nil {
			return err
		}
		if cmd.Flags().Changed("service") && len(f.Wait.Service) == 0 {
			return invalidCommandInput(cmd, errors.New("empty service"), "--service requires a service name.")
		}
		f.Wait.Service = append(f.Wait.Service, args...)
		if slices.Contains(f.Wait.Service, "") {
			return invalidCommandInput(cmd, errors.New("empty service"), "Service names must not be empty.")
		}
		if f.Wait.Timeout <= 0 {
			return invalidCommandInput(cmd, errors.New("nonpositive timeout"), "--timeout must be positive.")
		}
		return nil
	}
	return cWait
}

func (a *commandApp) newWatchCommand() *cobra.Command {
	f := a.flags
	cWatch := &cobra.Command{
		Use: "watch [service]", Short: "Follow this worktree's service events.", GroupID: "observe",
		Long:        "Follow all local publication events or name a single configured service. To resume without a snapshot, use the last event cursor from the same worktree and client state directory.",
		Annotations: map[string]string{"cliflags:arg:service": "Configured local service name."},
	}
	a.leaf(cWatch, &f.Watch, func(call commandCall) error {
		return runAppObservation(call.ctx, *f, "watch", a.out, a.errOut)
	})
	parseWatchFlags := cWatch.Args
	cWatch.Args = func(cmd *cobra.Command, args []string) error {
		if err := parseWatchFlags(cmd, nil); err != nil {
			return err
		}
		hasFlag := cmd.Flags().Changed
		switch {
		case len(args) > 1 || len(args) == 1 && hasFlag("service"):
			return invalidCommandInput(cmd, errors.New("multiple service names"), "Watch accepts one service name. Use a positional name or --service, not both.")
		case len(args) == 1 && args[0] == "" || hasFlag("service") && f.Watch.Service == "":
			return invalidCommandInput(cmd, errors.New("empty service"), "The service name must not be empty.")
		case hasFlag("count") && f.Watch.Count <= 0:
			return invalidCommandInput(cmd, errors.New("nonpositive count"), "--count must be positive.")
		case hasFlag("timeout") && f.Watch.Timeout <= 0:
			return invalidCommandInput(cmd, errors.New("nonpositive timeout"), "--timeout must be positive.")
		case hasFlag("after") && f.Watch.After == "":
			return invalidCommandInput(cmd, errors.New("empty cursor"), "--after requires a local event cursor.")
		}
		if len(args) == 1 {
			f.Watch.Service = args[0]
		}
		return nil
	}
	return cWatch
}
