package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
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
	configPath    string
	noConfig      bool
	configArgs    string
	diagnostics   io.Writer
}

type statusLocal struct {
	Available bool                       `json:"available"`
	CheckedAt time.Time                  `json:"checked_at"`
	Snapshot  publisherapp.Snapshot      `json:"snapshot"`
	Tunnels   clientstate.TunnelSnapshot `json:"tunnels"`
	readErr   error
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
	sourceName   string
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
	inventoryReason string
	declarations    controlv1.ProjectServiceDeclarations
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

func runStatus(ctx context.Context, flags statusCommand, output io.Writer) (resultErr error) {
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
	// a project can still have readable server inventory when its local journal
	// cannot be read. preserve the machine command's existing failure contract.
	allowPartial := !flags.All && flags.Scope == "both" && flags.Output != statusOutputJSON
	var localErr error
	defer func() {
		if localErr != nil {
			resultErr = errors.Join(localErr, resultErr)
		}
	}()
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
		if !allowPartial || ctx.Err() != nil {
			return err
		}
		localErr = err
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
		} else {
			appSnapshot, err = publisherapp.ReadSnapshotFrom(ctx, state, flags.Project)
			if err == nil {
				checkAppSnapshotOwner(ctx, state, &appSnapshot)
			}
		}
		if err != nil {
			if !allowPartial || ctx.Err() != nil {
				return err
			}
			localErr = errors.Join(localErr, err)
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
			entry.Local = &statusLocal{Available: localErr == nil, CheckedAt: time.Now().UTC(), Snapshot: appSnapshot, Tunnels: snapshot, readErr: localErr}
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
		for index := range projects {
			project := &projects[index]
			configuration := flags.Configuration
			var configErr error
			if flags.All {
				configuration, configErr = recordedStatusConfiguration(ctx, state, project.Project, flags)
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
			var localTunnels clientstate.TunnelSnapshot
			if project.Local != nil {
				localTunnels = project.Local.Tunnels
			} else {
				localTunnels, err = state.SnapshotProject(ctx, project.Project)
				if err != nil {
					return err
				}
				if flags.Service != "" {
					localTunnels.SelectService(flags.Service)
				}
			}
			selected := server
			switch {
			case flags.ServerURL != "":
				// the explicit server applies to every project.
			case configuration.Config.Server != nil:
				selected, err = clientstate.CanonicalServer(*configuration.Config.Server)
				if err != nil {
					return err
				}
				if flags.All && flags.AccessToken != "" && selected != server {
					project.Server = &statusServer{ControlURL: selected, CheckedAt: time.Now().UTC(), Reason: "select the project server with --server to use an explicit access token", Services: []statusServerService{}}
					continue
				}
			case len(localTunnels.Tunnels) != 0:
				selected = localTunnels.Tunnels[0].Server
				mixed := false
				for _, tunnel := range localTunnels.Tunnels {
					if tunnel.Server != selected {
						mixed = true
						break
					}
				}
				if mixed {
					project.Server = &statusServer{CheckedAt: time.Now().UTC(), Reason: "multiple local servers; select one with --server", Services: []statusServerService{}}
					continue
				}
			}
			project.Server = readStatusServer(ctx, state, selected, flags.AccessToken, project.Project)
			if configErr != nil {
				project.Server.AppliedReason = "selected project configuration unavailable"
			} else if configuration.Found() {
				readAppliedStatus(ctx, state, selected, flags.AccessToken, configuration, project.Server)
			}
			if flags.Service != "" {
				project.Server.selectService(flags.Service, localTunnels)
			}
		}
	}
	result := statusResult{SchemaVersion: 1, Scope: flags.Scope, Projects: projects}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	return writeStatus(output, flags, projects)
}

// a journal belongs to one project directory. an explicit file for one project
// and a configuration discovered in an ancestor must not select another's server.
func recordedStatusConfiguration(ctx context.Context, state *clientstate.Database, directory string, flags statusCommand) (projectConfiguration, error) {
	if flags.noConfig {
		return projectConfiguration{}, nil
	}
	root, err := filepath.EvalSymlinks(directory)
	if os.IsNotExist(err) {
		return projectConfiguration{}, nil
	}
	if err != nil {
		return projectConfiguration{}, err
	}
	path := flags.configPath
	if path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return projectConfiguration{}, err
		}
		dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil || dir != root {
			path = ""
		} else {
			path = filepath.Join(root, filepath.Base(absolute))
		}
	}
	selection, err := clientproject.SelectProjectConfig(ctx, root, path, "", false)
	if err != nil || selection.Path == "" || filepath.Dir(selection.Path) != root {
		return projectConfiguration{}, err
	}
	selection.Deployment = flags.Deployment
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return projectConfiguration{}, err
	}
	project, err := clientproject.Resolve(ctx, selection, root, salt)
	return projectConfiguration{Project: project}, err
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
		server.declarations = server.Applied.ServiceDeclarations
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
	server.Services = slices.DeleteFunc(server.Services, func(s statusServerService) bool { return s.Name != name && s.sourceName != name && !ids[s.ServiceID] })
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
	if applied.Deployment != project.Deployment {
		result.AppliedReason = "server returned another deployment"
		return
	}
	result.Applied = &applied
	result.inventoryReason = result.Reason
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
		if service.Source != nil {
			item.sourceName = service.Source.Service
		}
		if service.ServiceRunId != nil || service.RunNumber != nil {
			item.PublisherObservation = "ready_publisher_hint"
		}
		result = append(result, item)
	}
	return result
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
		f.Status.diagnostics = a.errOut
		f.Status.configArgs = configArgs(f.NoConfig, f.ConfigPath)
		f.Status.noConfig, f.Status.configPath = f.NoConfig, f.ConfigPath
		if f.Status.configPath == "" {
			f.Status.configPath = os.Getenv("TNL_CONFIG")
		}
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
