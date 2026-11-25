package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type statusOutputMode string

const (
	statusOutputHuman statusOutputMode = "human"
	statusOutputJSON  statusOutputMode = "json"
)

type statusCommand struct {
	Service       string           `name:"service" help:"Show only records for this service name."`
	Deployment    string           `name:"deployment" help:"Read this configured deployment's applied targets and publishers; defaults to local."`
	Output        statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	Scope         string           `name:"scope" enum:"local,server,both" default:"both" help:"Read local snapshots, fresh server state, or both (default)."`
	ServerURL     string           `name:"server" env:"TNL_SERVER" help:"Control URL to read; independent of --scope."`
	AccessToken   string           `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Access token for server status; defaults to saved session."`
	StateDir      string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	All           bool             `name:"all" help:"Show tunnels from every local project."`
	Project       string
	Configuration projectConfiguration
	configArgs    string
}

type statusLocal struct {
	Available bool                       `json:"available"`
	CheckedAt time.Time                  `json:"checked_at"`
	Snapshot  publisherapp.Snapshot      `json:"snapshot"`
	Tunnels   clientstate.TunnelSnapshot `json:"tunnels"`
}

type statusServerService struct {
	ServiceID            string                     `json:"service_id"`
	Name                 string                     `json:"name"`
	Enabled              bool                       `json:"enabled"`
	Endpoint             *controlv1.ServiceEndpoint `json:"endpoint,omitempty"`
	Protocol             controlv1.ServiceProtocol  `json:"protocol"`
	CreatedAt            time.Time                  `json:"created_at"`
	PublisherObservation string                     `json:"publisher_observation"`
	// these optional inventory hints neither select a visitor run nor establish
	// its current readiness or durable lifecycle state.
	ServiceRunID *controlv1.ServiceRunID `json:"service_run_id,omitempty"`
	RunNumber    *int64                  `json:"run_number,omitempty,string"`
}

type statusServer struct {
	AppliedServices []controlv1.AppliedProjectService      `json:"applied_services,omitempty"`
	Applied         *controlv1.AppliedProjectConfiguration `json:"applied,omitempty"`
	AppliedReason   string                                 `json:"applied_reason,omitempty"`
	Available       bool                                   `json:"available"`
	CheckedAt       time.Time                              `json:"checked_at"`
	ControlURL      string                                 `json:"control_url,omitempty"`
	Reason          string                                 `json:"reason,omitempty"`
	Services        []statusServerService                  `json:"services"`
}

type projectStatus struct {
	Project string        `json:"project"`
	Local   *statusLocal  `json:"local"`
	Server  *statusServer `json:"server"`
}

type statusResult struct {
	SchemaVersion int             `json:"schema_version"`
	Scope         string          `json:"scope"`
	Projects      []projectStatus `json:"projects"`
}

func runStatus(ctx context.Context, flags statusCommand, output io.Writer) error {
	if flags.Scope == "" {
		flags.Scope = "both"
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	root = state.Root()
	var snapshot clientstate.TunnelSnapshot
	if flags.All {
		snapshot, err = state.Snapshot(ctx)
	} else {
		if flags.Project == "" {
			flags.Project, err = currentProjectRoot(ctx)
			if err != nil {
				return err
			}
		}
		snapshot, err = state.SnapshotProject(ctx, flags.Project)
	}
	if err != nil {
		return err
	}
	appSnapshot := publisherapp.Snapshot{Services: []publisherapp.Service{}}
	var projectSnapshots []publisherapp.Snapshot
	if !flags.All {
		project, resolveErr := flags.Configuration, error(nil)
		if project.Root == "" {
			project, _, resolveErr = runtimeProject(ctx, runtimeOptions{Directory: flags.Project, StateDir: root})
		}
		if resolveErr == nil {
			appSnapshot, err = readAppSnapshotFrom(ctx, project, state)
			if err != nil {
				return err
			}
		} else {
			appSnapshot, err = publisherapp.ReadSnapshotFrom(ctx, state, flags.Project)
			if err != nil {
				return err
			}
			checkAppSnapshotOwner(ctx, state, &appSnapshot)
		}
	} else {
		projects, err := publisherapp.ListSnapshotsFrom(ctx, state)
		if err != nil {
			return err
		}
		projectSnapshots = projects
		for index := range projectSnapshots {
			checkAppSnapshotOwner(ctx, state, &projectSnapshots[index])
		}
	}
	projects := []projectStatus{}
	if flags.All {
		for _, project := range projectSnapshots {
			entry := projectStatus{Project: project.Project}
			if flags.Scope != "server" {
				projectTunnels, readErr := state.SnapshotProject(ctx, project.Project)
				if readErr != nil {
					return readErr
				}
				entry.Local = &statusLocal{Available: true, CheckedAt: time.Now().UTC(), Snapshot: project, Tunnels: projectTunnels}
			}
			projects = append(projects, entry)
		}
		// tunnels without an app journal still belong to their own project.
		for _, tunnel := range snapshot.Tunnels {
			found := false
			for _, project := range projects {
				if project.Project == tunnel.Project {
					found = true
					break
				}
			}
			if !found {
				local, readErr := publisherapp.ReadSnapshotFrom(ctx, state, tunnel.Project)
				if readErr != nil {
					return readErr
				}
				checkAppSnapshotOwner(ctx, state, &local)
				entry := projectStatus{Project: tunnel.Project}
				if flags.Scope != "server" {
					projectTunnels, readErr := state.SnapshotProject(ctx, tunnel.Project)
					if readErr != nil {
						return readErr
					}
					entry.Local = &statusLocal{Available: true, CheckedAt: time.Now().UTC(), Snapshot: local, Tunnels: projectTunnels}
				}
				projects = append(projects, entry)
			}
		}
	} else {
		entry := projectStatus{Project: flags.Project}
		if flags.Scope != "server" {
			entry.Local = &statusLocal{Available: true, CheckedAt: time.Now().UTC(), Snapshot: appSnapshot, Tunnels: snapshot}
		}
		projects = append(projects, entry)
	}
	if flags.Service != "" {
		for _, p := range projects {
			if local := p.Local; local != nil {
				local.Snapshot.Services = slices.DeleteFunc(local.Snapshot.Services, func(s publisherapp.Service) bool { return s.Name != flags.Service })
				local.Snapshot.Publications = slices.DeleteFunc(local.Snapshot.Publications, func(t clientstate.TunnelInfo) bool { return t.Service != flags.Service })
				local.Tunnels.SelectService(flags.Service)
			}
		}
	}
	if flags.Scope != "local" {
		server, selectErr := clientserver.Select(ctx, state, flags.ServerURL)
		if selectErr != nil {
			return selectErr
		}
		if flags.ServerURL == "" && flags.Configuration.Config.Server != nil && !flags.All {
			server, selectErr = clientstate.CanonicalServer(*flags.Configuration.Config.Server)
			if selectErr != nil {
				return selectErr
			}
		}
		for index := range projects {
			var localTunnels clientstate.TunnelSnapshot
			if projects[index].Local != nil {
				localTunnels = projects[index].Local.Tunnels
			} else {
				localTunnels, err = state.SnapshotProject(ctx, projects[index].Project)
				if err != nil {
					return err
				}
				if flags.Service != "" {
					localTunnels.SelectService(flags.Service)
				}
			}
			selected := server
			if flags.ServerURL == "" && (flags.All || flags.Configuration.Config.Server == nil) && len(localTunnels.Tunnels) != 0 {
				selected = localTunnels.Tunnels[0].Server
				mixed := false
				for _, tunnel := range localTunnels.Tunnels {
					if tunnel.Server != selected {
						mixed = true
						break
					}
				}
				if mixed {
					projects[index].Server = &statusServer{CheckedAt: time.Now().UTC(), Reason: "multiple local servers; select one with --server", Services: []statusServerService{}}
					continue
				}
			}
			projects[index].Server = readStatusServer(ctx, state, selected, flags.AccessToken, projects[index].Project)
			configuration := flags.Configuration
			if flags.All {
				configuration, _, _ = runtimeProject(ctx, runtimeOptions{Directory: projects[index].Project, StateDir: root})
			}
			if configuration.Found() {
				readAppliedStatus(ctx, state, selected, flags.AccessToken, configuration, projects[index].Server)
			}
			if flags.Service != "" {
				projects[index].Server.selectService(flags.Service, localTunnels)
			}
		}
	}
	result := statusResult{SchemaVersion: 1, Scope: flags.Scope, Projects: projects}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	return writeStatus(output, flags, projects)
}

func writeStatus(output io.Writer, flags statusCommand, projects []projectStatus) error {
	var blocks []clioutput.Block
	names := map[string]int{}
	if flags.All {
		for _, project := range projects {
			names[filepath.Base(project.Project)]++
		}
	}
	for _, project := range projects {
		if flags.All {
			name := filepath.Base(project.Project)
			if names[name] > 1 {
				name = project.Project
			}
			blocks = append(blocks, clioutput.Line("Project: "+name))
		}
		if project.Local != nil {
			blocks = append(blocks, localStatusBlocks(project.Local, flags)...)
		}
		if project.Server != nil {
			blocks = append(blocks, serverStatusBlocks(project, flags)...)
		}
	}
	if len(projects) == 0 {
		blocks = append(blocks, clioutput.Text("No projects recorded locally."))
	}
	return writeResult(output, blocks...)
}

func localStatusBlocks(local *statusLocal, flags statusCommand) []clioutput.Block {
	var blocks []clioutput.Block
	for _, entry := range snapshotObservations(local.Snapshot.Services, local.Tunnels.Tunnels) {
		if entry.row.state == string(clientstate.TunnelStateStale) && !entry.lastSeen.IsZero() && !local.CheckedAt.Before(entry.lastSeen) {
			age := local.CheckedAt.Sub(entry.lastSeen)
			label := "less than a minute"
			switch {
			case age >= 24*time.Hour:
				label = countState(int(age/(24*time.Hour)), "day", "days")
			case age >= time.Hour:
				label = countState(int(age/time.Hour), "hour", "hours")
			case age >= time.Minute:
				label = countState(int(age/time.Minute), "minute", "minutes")
			}
			entry.row.state += " (last seen " + label + " ago)"
		}
		blocks = append(blocks, entry.row.blocks()...)
		if _, configured := flags.Configuration.Config.Services[entry.key]; !flags.All && entry.canWait && configured {
			cmd := "tnl " + flags.configArgs + "wait --service " + shellWord(entry.key)
			if flags.StateDir != "" {
				cmd += " --state-dir=" + shellWord(flags.StateDir)
			}
			blocks = append(blocks, clioutput.Line("Check now: "+cmd))
		}
	}
	addIntegration := func(row observationRow, action string) {
		blocks = append(blocks, row.blocks()...)
		if action != "" {
			blocks = append(blocks, clioutput.Line(action))
		}
	}
	for _, u := range local.Tunnels.IntegrationURLs {
		addIntegration(observationRow{name: u.Kind, state: u.State, address: u.PublicURL, lastError: observationError(string(u.Reason))}, u.Action)
		for _, e := range u.Endpoints {
			addIntegration(observationRow{name: "webhook " + e.Name + " -> " + e.Service, state: e.State, address: e.URL, lastError: observationError(string(e.Reason))}, e.Action)
		}
	}
	for _, a := range local.Tunnels.Aliases {
		addIntegration(observationRow{name: "alias " + a.Name + " -> " + a.Service, state: a.State, address: a.PublicURL, lastError: observationError(string(a.Reason))}, a.Action)
		if a.SelectedProject != "" && a.SelectedProject != local.Snapshot.Project {
			blocks = append(blocks, clioutput.Line("Selected worktree: "+a.SelectedProject))
		}
	}
	if len(blocks) == 0 {
		switch deployment := config.SelectedDeployment(flags.Configuration.Config); {
		case !flags.All && deployment != "local":
			blocks = append(blocks, clioutput.Text("Deployment "+deployment+" is remote. No local publications."))
		case flags.Service != "":
			blocks = append(blocks, clioutput.Text("No local publication for "+flags.Service+"."))
		default:
			blocks = append(blocks, clioutput.Text("No local publications."))
		}
	}
	return blocks
}

func serverStatusBlocks(project projectStatus, flags statusCommand) []clioutput.Block {
	server := project.Server
	var blocks []clioutput.Block
	if !server.Available {
		if server.Reason == "no local service IDs for this project" {
			if project.Local == nil {
				blocks = append(blocks, clioutput.Text("No saved services to look up on the server."))
			}
		} else {
			blocks = append(blocks, clioutput.Text("Server status unavailable: "+server.Reason))
		}
	}
	for _, s := range server.Services {
		// a matching server hint adds no readiness proof to a local publication.
		if s.Enabled && s.PublisherObservation == "ready_publisher_hint" && project.Local != nil && s.ServiceID != "" &&
			slices.ContainsFunc(project.Local.Tunnels.Tunnels, func(t clientstate.TunnelInfo) bool {
				if t.State != clientstate.TunnelStateReady || t.Server != server.ControlURL || t.ServiceID != s.ServiceID {
					return false
				}
				addr, err := servicePublicAddress(s.Protocol, s.Endpoint)
				return err == nil && t.PublicURL == addr
			}) {
			continue
		}
		blocks = append(blocks, statusServiceRow(s).blocks()...)
	}
	services := server.AppliedServices
	if applied := server.Applied; applied != nil {
		services = applied.Services
		if applied.RetiredAt != nil {
			blocks = append(blocks, clioutput.Line("Deployment "+applied.Deployment+": retired"))
		}
		for _, member := range applied.Members {
			health := "not healthy"
			if member.Healthy {
				health = "healthy"
			}
			if member.Runtime != nil && !member.Runtime.Active {
				health += ", last observed process offline"
			}
			label := "Publisher for " + member.DeploymentName
			if member.Runtime != nil && member.Runtime.Deployment != nil && member.Runtime.Deployment.Report.Instance != "" {
				label += " (" + member.Runtime.Deployment.Report.Instance + ")"
			}
			blocks = append(blocks, clioutput.Line(label+": "+health))
		}
	}
	for _, binding := range services {
		if binding.Deployment == "local" && project.Local != nil && slices.ContainsFunc(project.Local.Snapshot.Services, func(s publisherapp.Service) bool { return s.Name == binding.Service }) {
			continue
		}
		row := observationRow{name: binding.Service, state: "configured in " + binding.Deployment}
		if binding.Public != nil && !*binding.Public {
			row.state += ", connector-only"
		} else if binding.Public != nil {
			row.state += ", public endpoint"
			if server.Applied != nil && binding.Hostname != nil && binding.Port != nil {
				protocol := server.Applied.ServiceDeclarations[binding.Service]
				row.address, _ = servicePublicAddress(protocol, &controlv1.ServiceEndpoint{Public: true, Hostname: *binding.Hostname, Port: *binding.Port})
			}
		}
		blocks = append(blocks, row.blocks()...)
	}
	if server.AppliedReason != "" && (server.Available || server.AppliedReason != server.Reason) {
		blocks = append(blocks, clioutput.Text("Applied configuration: "+server.AppliedReason))
	}
	if server.Available && len(server.Services)+len(services) == 0 && (flags.Service != "" || project.Local == nil) {
		message := "No server service records."
		if flags.Service != "" {
			message = "No server record for " + flags.Service + "."
		}
		blocks = append(blocks, clioutput.Text(message))
	}
	if len(blocks) != 0 && server.ControlURL != "" {
		blocks = append([]clioutput.Block{clioutput.Line("Server: " + server.ControlURL)}, blocks...)
	}
	return blocks
}

func (server *statusServer) selectService(name string, local clientstate.TunnelSnapshot) {
	ids := map[string]bool{}
	for _, tunnel := range local.Tunnels {
		if tunnel.Server == server.ControlURL && tunnel.Service == name {
			ids[tunnel.ServiceID] = true
		}
	}
	for _, a := range local.Aliases {
		if a.Server == server.ControlURL && a.Service == name {
			ids[a.ServiceID] = true
		}
	}
	// the hash identifies the complete applied configuration. emit only the
	// matching binding records rather than attaching it to a partial config.
	if server.Applied != nil {
		for _, s := range server.Applied.Services {
			if s.Service == name {
				server.AppliedServices = append(server.AppliedServices, s)
				if s.ServiceId != nil {
					ids[*s.ServiceId] = true
				}
			}
		}
		server.Applied = nil
	}
	server.Services = slices.DeleteFunc(server.Services, func(s statusServerService) bool { return s.Name != name && !ids[s.ServiceID] })
}

func readAppliedStatus(ctx context.Context, state *clientstate.Database, server, token string, project projectConfiguration, result *statusServer) {
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		result.AppliedReason = "portable Git configuration source unavailable"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	auth, err := auth.Authenticate(ctx, auth.Config{ServerEndpoint: server, State: state, AccessToken: token})
	if err != nil {
		result.AppliedReason = "control API or signed-in session unavailable"
		return
	}
	identity, err := auth.Authority.IdentityContext(ctx)
	if err != nil {
		result.AppliedReason = "identity inventory unavailable"
		return
	}
	profile, err := state.Server(ctx, server)
	if err != nil {
		result.AppliedReason = "client state unavailable"
		return
	}
	team, err := resolve.TeamForServer(server, project.Config.Server, project.Config.Team)
	if err != nil {
		result.AppliedReason = "project team selection unavailable"
		return
	}
	session := clientteam.NewSession(nil, profile, auth, identity, clientteam.Options{ProjectTeam: team})
	current, err := session.Current(ctx)
	if err != nil {
		result.AppliedReason = "select a project team"
		return
	}
	applied, err := auth.Control.GetProjectConfiguration(ctx, current.Team().Id, source.Key, project.Deployment)
	if err != nil {
		result.AppliedReason = "not applied or unavailable; run tnl apply"
		return
	}
	if applied.SourceFingerprint != source.Fingerprint || applied.ProjectKey != source.Key || applied.TeamId != current.Team().Id {
		result.AppliedReason = "server returned another project source"
		return
	}
	result.Applied = &applied
	result.Available, result.Reason = true, ""
}

func readStatusServer(ctx context.Context, state *clientstate.Database, server, token, project string) *statusServer {
	result := &statusServer{CheckedAt: time.Now().UTC(), ControlURL: server, Services: []statusServerService{}}
	server, err := clientstate.CanonicalServer(server)
	if err != nil {
		result.Reason = "control URL unavailable"
		return result
	}
	result.ControlURL = server
	ids := map[string]bool{}
	known, err := state.KnownProjectServices(ctx, project, server)
	if err != nil {
		result.Reason = "local service inventory unavailable"
		return result
	}
	// aliases have no owning-project field. SnapshotProject applies the saved
	// declaration/primary/selected-worktree scope; SelectedProject alone cannot.
	tunnels, err := state.SnapshotProject(ctx, project)
	if err != nil {
		result.Reason = "local service journal unavailable"
		return result
	}
	for _, id := range known {
		ids[id] = true
	}
	for _, tunnel := range tunnels.Tunnels {
		if tunnel.Project == project && tunnel.Server == server && tunnel.ServiceID != "" {
			ids[tunnel.ServiceID] = true
		}
	}
	for _, alias := range tunnels.Aliases {
		if alias.Server == server && alias.ServiceID != "" {
			ids[alias.ServiceID] = true
		}
	}
	if len(ids) == 0 {
		result.Reason = "no local service IDs for this project"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	auth, err := auth.Authenticate(ctx, auth.Config{ServerEndpoint: server, State: state, AccessToken: token})
	if err != nil {
		result.Reason = "control API or signed-in session unavailable"
		return result
	}
	identity, err := auth.Authority.IdentityContext(ctx)
	if err != nil {
		result.Reason = "identity inventory unavailable"
		return result
	}
	teams := map[string]bool{}
	for _, membership := range identity.Memberships {
		if len(ids) == 0 {
			break
		}
		if teams[membership.TeamId] {
			continue
		}
		teams[membership.TeamId] = true
		services, err := auth.Control.ListServices(ctx, membership.TeamId)
		if err != nil {
			result.Reason = "service inventory unavailable"
			result.Services = []statusServerService{}
			return result
		}
		result.Services = append(result.Services, statusServicesForProject(services, ids)...)
	}
	result.Available = true
	return result
}

func statusServicesForProject(services []controlv1.ServiceSummary, ids map[string]bool) []statusServerService {
	result := []statusServerService{}
	for _, service := range services {
		if !ids[service.Id] {
			continue
		}
		delete(ids, service.Id)
		item := statusServerService{
			ServiceID: service.Id, Name: service.Name, Enabled: service.Enabled,
			Endpoint: service.Endpoint, Protocol: service.Protocol, CreatedAt: service.CreatedAt,
			ServiceRunID: service.ServiceRunId, RunNumber: service.RunNumber,
			PublisherObservation: "no_ready_publisher_observed",
		}
		if service.ServiceRunId != nil || service.RunNumber != nil {
			item.PublisherObservation = "ready_publisher_hint"
		}
		result = append(result, item)
	}
	return result
}

func statusServiceRow(s statusServerService) observationRow {
	state := "disabled"
	if s.Enabled {
		state = "enabled"
	}
	facts := []string{state}
	if s.Protocol != "" {
		facts = append(facts, string(s.Protocol))
	}
	address := ""
	switch {
	case s.Endpoint == nil:
		facts = append(facts, "endpoint not reported")
	case !s.Endpoint.Public:
		facts = append(facts, "connector-only")
		if s.Endpoint.Port > 0 && s.Protocol != controlv1.ServiceProtocolHTTP {
			facts = append(facts, "port "+strconv.Itoa(s.Endpoint.Port)+" reserved")
		}
	default:
		address, _ = servicePublicAddress(s.Protocol, s.Endpoint)
	}
	if s.PublisherObservation == "ready_publisher_hint" {
		facts = append(facts, "publisher reported; readiness not checked")
	} else {
		facts = append(facts, "no ready publisher reported")
	}
	return observationRow{name: s.Name, state: strings.Join(facts, ", "), address: address}
}

func currentProjectRoot(ctx context.Context) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	worktree, err := clientproject.ResolveWorktree(ctx, cwd)
	if err != nil {
		return "", err
	}
	return worktree.Root, nil
}

func (a *commandApp) newStatusCommand() *cobra.Command {
	f := a.flags
	const summary = "Show the status of services in this project."
	cStatus := &cobra.Command{
		Use: "status", Short: summary, GroupID: "start",
		Long: summary + "\n\nRead recorded local state and, when signed in, current server state. Use tnl wait to check readiness now or tnl watch to follow changes.",
	}
	a.leaf(cStatus, &f.Status, func(call commandCall) error {
		f.Status.configArgs = configArgs(f.NoConfig, f.ConfigPath)
		if !f.Status.All {
			var err error
			f.Status.Project, err = projectRoot(call.ctx, *f)
			if err != nil {
				return err
			}
			stateRoot, err := clientStateRoot(f.Status.StateDir)
			if err != nil {
				return err
			}
			f.Status.Configuration, err = loadProjectConfiguration(call.ctx, *f, stateRoot)
			if err != nil {
				return err
			}
		}
		return runStatus(call.ctx, f.Status, a.out)
	})
	return cStatus
}
