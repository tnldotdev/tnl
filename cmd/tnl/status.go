package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type statusOutputMode string

const (
	statusOutputHuman statusOutputMode = "human"
	statusOutputJSON  statusOutputMode = "json"
)

type statusCommand struct {
	Deployment    string           `name:"deployment" help:"Read this configured deployment's applied targets and publishers; defaults to local."`
	Output        statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	Scope         string           `name:"scope" enum:"local,server,both" default:"both" help:"Read local snapshots, fresh server state, or both (default)."`
	ServerURL     string           `name:"server" env:"TNL_SERVER" help:"Control URL to read; independent of --scope."`
	AccessToken   string           `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Access token for server status; defaults to saved session."`
	StateDir      string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	All           bool             `name:"all" help:"Show tunnels from every local project."`
	Project       string
	Configuration projectConfiguration
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
	Applied       *controlv1.AppliedProjectConfiguration `json:"applied,omitempty"`
	AppliedReason string                                 `json:"applied_reason,omitempty"`
	Available     bool                                   `json:"available"`
	CheckedAt     time.Time                              `json:"checked_at"`
	ControlURL    string                                 `json:"control_url,omitempty"`
	Reason        string                                 `json:"reason,omitempty"`
	Services      []statusServerService                  `json:"services"`
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
		}
	}
	result := statusResult{SchemaVersion: 1, Scope: flags.Scope, Projects: projects}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	blocks := []clioutput.Block{}
	for _, project := range projects {
		fields := []clioutput.Field{{Label: "project", Value: project.Project}}
		if project.Local != nil {
			fields = append(fields, clioutput.Field{Label: "local snapshot at", Value: project.Local.CheckedAt.Format(time.RFC3339Nano)}, clioutput.Field{Label: "local cursor", Value: project.Local.Snapshot.Cursor})
			if !project.Local.Snapshot.ObservedAt.IsZero() {
				fields = append(fields, clioutput.Field{Label: "local updated at", Value: project.Local.Snapshot.ObservedAt.Format(time.RFC3339Nano)})
			}
		}
		if project.Server != nil {
			fields = append(fields, clioutput.Field{Label: "server", Value: project.Server.ControlURL}, clioutput.Field{Label: "server checked at", Value: project.Server.CheckedAt.Format(time.RFC3339Nano)})
			if !project.Server.Available {
				fields = append(fields, clioutput.Field{Label: "server", Value: "unavailable: " + project.Server.Reason})
			}
		}
		blocks = append(blocks, clioutput.Section("project", clioutput.Fields(fields...)))
		if project.Local != nil {
			blocks = append(blocks, appServiceBlocks(project.Local.Snapshot)...)
			if len(project.Local.Snapshot.Services) == 0 && len(project.Local.Tunnels.Tunnels) == 0 {
				blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "local", Value: "no local publications; start an app or run tnl publish 3000"}))
			}
			for _, tunnel := range project.Local.Tunnels.Tunnels {
				blocks = append(blocks, clioutput.Section("local "+string(tunnel.State), clioutput.Fields(clioutput.Field{Label: "public URL", Value: tunnel.PublicURL}, clioutput.Field{Label: "tunnel", Value: tunnel.ID}, clioutput.Field{Label: "updated at", Value: tunnel.UpdatedAt.Format(time.RFC3339Nano)})))
			}
			for _, url := range project.Local.Tunnels.IntegrationURLs {
				blocks = append(blocks, clioutput.Section("local "+url.Kind+" "+url.State, clioutput.Fields(clioutput.Field{Label: "public URL", Value: url.PublicURL}, clioutput.Field{Label: "server", Value: url.Server}, clioutput.Field{Label: "reason", Value: string(url.Reason)}, clioutput.Field{Label: "action", Value: url.Action})))
				for _, endpoint := range url.Endpoints {
					blocks = append(blocks, clioutput.Section("local webhook "+endpoint.Name+" "+endpoint.State, clioutput.Fields(clioutput.Field{Label: "endpoint", Value: endpoint.URL}, clioutput.Field{Label: "service", Value: endpoint.Service}, clioutput.Field{Label: "delivery", Value: endpoint.Delivery}, clioutput.Field{Label: "ready receivers", Value: strconv.Itoa(len(endpoint.ReadyReceivers))}, clioutput.Field{Label: "reason", Value: string(endpoint.Reason)}, clioutput.Field{Label: "action", Value: endpoint.Action})))
				}
			}
			for _, alias := range project.Local.Tunnels.Aliases {
				blocks = append(blocks, clioutput.Section("local alias "+alias.State, clioutput.Fields(clioutput.Field{Label: "alias", Value: alias.Name}, clioutput.Field{Label: "public URL", Value: alias.PublicURL}, clioutput.Field{Label: "service", Value: alias.Service}, clioutput.Field{Label: "selected worktree", Value: alias.SelectedProject}, clioutput.Field{Label: "reason", Value: string(alias.Reason)}, clioutput.Field{Label: "action", Value: alias.Action})))
			}
		}
		if project.Server != nil && project.Server.Available {
			blocks = append(blocks, statusServiceBlocks(project.Server.Services)...)
		}
		if project.Server != nil && project.Server.Applied != nil {
			blocks = append(blocks, appliedProjectBlocks(*project.Server.Applied)...)
		} else if project.Server != nil && project.Server.AppliedReason != "" {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "applied configuration", Value: project.Server.AppliedReason}))
		}
	}
	return writeHumanFrame(output, "tnl status", countState(len(projects), "project", "projects"), "", blocks...)
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

func statusServiceBlocks(services []statusServerService) []clioutput.Block {
	blocks := make([]clioutput.Block, 0, len(services))
	for _, service := range services {
		state := "disabled"
		if service.Enabled {
			state = "enabled"
		}
		fields := []clioutput.Field{
			{Label: "service", Value: service.Name},
			{Label: "service ID", Value: service.ServiceID},
			{Label: "protocol", Value: string(service.Protocol)},
			{Label: "created at", Value: service.CreatedAt.Format(time.RFC3339Nano)},
		}
		if service.Endpoint != nil {
			fields = append(fields,
				clioutput.Field{Label: "hostname", Value: service.Endpoint.Hostname},
				clioutput.Field{Label: "public", Value: strconv.FormatBool(service.Endpoint.Public)},
				clioutput.Field{Label: "endpoint port", Value: strconv.Itoa(service.Endpoint.Port)},
			)
		} else {
			fields = append(fields, clioutput.Field{Label: "endpoint", Value: "not reported"})
		}
		observation := "no ready publisher observed"
		if service.PublisherObservation == "ready_publisher_hint" {
			observation = "ready publisher hint; not a selected visitor run"
		}
		fields = append(fields, clioutput.Field{Label: "publisher", Value: observation})
		if service.ServiceRunID != nil {
			fields = append(fields, clioutput.Field{Label: "service run ID hint", Value: *service.ServiceRunID})
		}
		if service.RunNumber != nil {
			fields = append(fields, clioutput.Field{Label: "run number hint", Value: strconv.FormatInt(*service.RunNumber, 10)})
		}
		blocks = append(blocks, clioutput.Section("server "+state, clioutput.Fields(fields...)))
	}
	return blocks
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
	cStatus := &cobra.Command{Use: "status", Short: "Show local snapshots and fresh signed-in server facts; --all includes other projects.", GroupID: "start"}
	a.leaf(cStatus, &f.Status, func(call commandCall) error {
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
