package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type connectCommand struct {
	Start          connectStartCommand     `cmd:"" default:"withargs" help:"Make an approved service available locally until stopped; start is optional and disambiguates command names."`
	Available      connectAvailableCommand `cmd:"" help:"List services this identity can visit."`
	List           connectListCommand      `cmd:"" help:"List installed local connectors."`
	Stop           connectJobCommand       `cmd:"" help:"Stop an installed connector without revoking access."`
	Remove         connectJobCommand       `cmd:"" help:"Remove an installed connector and its remembered port."`
	KubeCredential kubeCredentialCommand   `cmd:"" hidden:""`
}

type connectStartCommand struct {
	scopedTeamFlags `embed:""`
	Name            string           `arg:"" name:"name" help:"Configured service name or exact service ID."`
	Listen          string           `name:"listen" help:"Loopback IP and port; defaults to 127.0.0.1 and the allocated service port."`
	Protocol        string           `name:"protocol" help:"Require an exact match: http, tcp, mysql, postgres, or kubernetes."`
	Kubeconfig      string           `name:"kubeconfig" type:"path" help:"Kubeconfig to register the owned Kubernetes context; defaults to KUBECONFIG or ~/.kube/config."`
	Namespace       string           `name:"namespace" help:"Default Kubernetes namespace for this context."`
	KubeUserConfig  string           `name:"kube-user-config" type:"path" help:"Existing kubeconfig containing the explicitly selected bearer-token user."`
	KubeUser        string           `name:"kube-user" help:"Exact existing Kubernetes user; explicitly permits that user's noninteractive exec plugin."`
	KubeTokenFile   string           `name:"kube-token-file" type:"path" help:"Private file containing the cluster bearer token."`
	Foreground      bool             `name:"foreground" help:"Run in this terminal (the default)."`
	Detach          bool             `name:"detach" help:"Run independently of this terminal without automatic restart."`
	Install         bool             `name:"install" help:"Keep this connector running with the installed user supervisor."`
	System          bool             `name:"system" hidden:""`
	SystemStateDir  string           `name:"system-state-dir" type:"path" help:"Private user supervisor state directory."`
	DetachedChild   string           `name:"detached-child" hidden:""`
	Stdio           bool             `name:"stdio" help:"Carry one opaque TCP stream on stdin/stdout; sign in explicitly before use."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Ready local connection address and native client instructions."`
	project         projectConfiguration
	detach          func() error
}

type connectListCommand struct {
	SystemStateDir string           `name:"system-state-dir" type:"path" help:"Private user supervisor state directory."`
	Output         statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type connectJobCommand struct {
	connectListCommand `embed:""`
	Name               string `arg:"" name:"name" help:"Installed connector name or job ID."`
}

func validateConnectMode(flags connectStartCommand) error {
	if flags.Stdio && (flags.Listen != "" || flags.Install || flags.Detach || flags.Foreground || flags.DetachedChild != "" || flags.Output == statusOutputJSON) {
		return connectModeError(failure.ConnectModeInvalid)
	}
	if flags.Protocol != "" && !config.ValidProtocol(flags.Protocol) {
		return publisherCLIError("--protocol must be http, tcp, mysql, postgres, or kubernetes")
	}
	if (flags.KubeUserConfig == "") != (flags.KubeUser == "") || flags.KubeTokenFile != "" && flags.KubeUser != "" {
		return publisherCLIError("select --kube-token-file, or both --kube-user-config and --kube-user")
	}
	if flags.System {
		return publisherCLIError("connectors use the user supervisor; --system is only for explicit publishers")
	}
	if flags.Install && flags.Detach || flags.Foreground && (flags.Install || flags.Detach) {
		return connectModeError(failure.ConnectModeInvalid)
	}
	if flags.SystemStateDir != "" && !flags.Install {
		return publisherCLIError("--system-state-dir requires --install")
	}
	if flags.Install && flags.AccessToken != "" {
		return publisherCLIError("installed connectors require a saved sign-in; access tokens are not installed")
	}
	return nil
}

func connectModeError(reason failure.Reason) error {
	return failure.Wrap("select connection mode", reason, errors.New("connect mode validation failed"))
}

func validateConnectServiceMode(flags connectStartCommand, service controlv1.PrivateService) error {
	if err := validateProfileService(service); err != nil {
		return err
	}
	if config.ProtocolName(service.Protocol) != config.ProtocolKubernetes && (flags.Kubeconfig != "" || flags.Namespace != "" || flags.KubeUserConfig != "" || flags.KubeUser != "" || flags.KubeTokenFile != "") {
		return publisherCLIError("kubeconfig and namespace options require protocol kubernetes")
	}
	if service.Protocol == controlv1.Mysql {
		if _, err := nativeMySQLRoots(); err != nil {
			return err
		}
	}
	if flags.Protocol != "" && flags.Protocol != string(service.Protocol) {
		return connectModeError(failure.ConnectProtocolMismatch)
	}
	if flags.Stdio && service.Protocol != controlv1.Tcp {
		return connectModeError(failure.ConnectStdioProtocolInvalid)
	}
	return nil
}

// named publishers' public_url blocks are managed HTTP policy, not public URLs.
func isConnectPublicURL(service config.Service) bool {
	return config.PublisherName(service) == "local" && config.IsPublicService(service)
}

func privateServiceSelection(services []controlv1.PrivateService, name, team string) (controlv1.PrivateService, error) {
	for _, service := range services {
		if service.Id == name && (team == "" || team == service.TeamId) {
			return service, nil
		}
	}
	var selected controlv1.PrivateService
	for _, service := range services {
		if (service.Id == name || service.Name == name) && (team == "" || team == service.TeamId) {
			if selected.Id != "" && selected.Id != service.Id {
				return selected, publisherCLIError("private service name is ambiguous; pass its ID or select --team")
			}
			selected = service
		}
	}
	if selected.Id == "" {
		return selected, failure.Wrap("select private service", failure.ServerResourceNotFound, errors.New("private service is not available to this identity; run tnl connect available"))
	}
	return selected, nil
}

func privateServiceIDSelection(services []controlv1.PrivateService, id, team string) (controlv1.PrivateService, error) {
	for _, service := range services {
		if service.Id == id && (team == "" || service.TeamId == team) {
			return service, nil
		}
	}
	return controlv1.PrivateService{}, failure.Wrap("select private service ID", failure.ServerResourceNotFound, errors.New("private service ID is absent from visitor inventory"))
}

// a configured key and its unique saved-name override select the same declaration.
// reject overlapping aliases rather than choosing a map iteration's first match.
func configuredConnectService(project projectConfiguration, name string) (string, error) {
	selected := ""
	publicMatch := false
	for key, service := range project.Config.Services {
		if key != name && config.ServiceName(key, service) != name {
			continue
		}
		if isConnectPublicURL(service) {
			publicMatch = true
			continue
		}
		if selected != "" {
			return "", publisherCLIError("configured private service name is ambiguous; use an unambiguous service key or --no-config with the service ID")
		}
		selected = key
	}
	if publicMatch {
		return "", publisherCLIError("configured name selects a public URL service; use its HTTPS URL or --no-config with an exact private service ID")
	}
	return selected, nil
}

func (project projectConfiguration) applyConnect(flags *connectStartCommand) error {
	remote, err := project.connectScope(flags.Name, flags.scopedTeamFlags)
	if err != nil {
		return err
	}
	flags.project, flags.scopedTeamFlags = project, remote
	return nil
}

func (project projectConfiguration) connectScope(name string, remote scopedTeamFlags) (scopedTeamFlags, error) {
	key, err := configuredConnectService(project, name)
	if err != nil {
		return remote, err
	}
	effective, err := project.EffectiveService(key)
	if err != nil {
		return remote, err
	}
	remote.ServerURL, _, err = resolveProjectServer(remote.ServerURL, effective.Server, remote.AccessToken)
	if err != nil {
		return remote, err
	}
	remote.ProjectTeam, err = projectTeamForServer(remote.ServerURL, effective.Server, effective.Team)
	return remote, err
}

type connectInventoryReader interface {
	ListAvailablePrivateServices(context.Context) ([]controlv1.PrivateService, error)
}

type connectServiceReader interface {
	connectInventoryReader
	GetLocalProjectService(context.Context, string, string, controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error)
	GetProjectPrivateService(context.Context, string, string, controlv1.GetProjectPrivateServiceParams) (controlv1.PrivateService, error)
}

func selectConnectService(ctx context.Context, control connectServiceReader, project projectConfiguration, name, team string) (controlv1.PrivateService, error) {
	key, err := configuredConnectService(project, name)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	localID := ""
	if key != "" {
		definition := project.Config.Services[key]
		if config.PublisherName(definition) == "local" {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.PrivateService{}, failure.Wrap("identify local project service", failure.ProjectConfigInvalid, err)
			}
			params := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey()}
			bound, err := control.GetLocalProjectService(ctx, source.Key, key, params)
			if errors.Is(err, controlclient.ErrNotFound) {
				return controlv1.PrivateService{}, failure.Wrap("find local private service", failure.LocalPrivateServiceUnavailable, err)
			}
			if err != nil {
				return controlv1.PrivateService{}, err
			}
			if bound.Service != key || bound.WorktreeKey != params.WorktreeKey || bound.ServiceKind != controlv1.LocalProjectServiceServiceKindPrivateService || bound.ServiceId == "" || bound.PrivateService == nil {
				return controlv1.PrivateService{}, failure.Wrap("find local private service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
			}
			localID = bound.ServiceId
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.PrivateService{}, failure.Wrap("identify applied project service", failure.ProjectConfigInvalid, err)
			}
			return control.GetProjectPrivateService(ctx, source.Key, key, controlv1.GetProjectPrivateServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint})
		}
	}
	services, err := control.ListAvailablePrivateServices(ctx)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	if localID != "" {
		service, err := privateServiceIDSelection(services, localID, team)
		if err != nil {
			return service, failure.Wrap("select local private service", failure.LocalPrivateServiceUnavailable, err)
		}
		return service, nil
	}
	return privateServiceSelection(services, name, team)
}

func connectListen(value string) (string, error) {
	if _, err := strconv.Atoi(value); err == nil {
		value = net.JoinHostPort("127.0.0.1", value)
	}
	host, port, err := net.SplitHostPort(value)
	address := net.ParseIP(host)
	n, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || n < 1 || n > 65535 || address == nil || !address.IsLoopback() {
		return "", publisherCLIError("--listen requires a loopback IP and a port from 1 to 65535, such as 127.0.0.1:15432")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(n)), nil
}

func runConnectStart(ctx context.Context, flags connectStartCommand, output, diagnostics io.Writer) (result error) {
	ctx, finishStartup := observability.ClientOperation(ctx, "client.connect.startup")
	defer func() { finishStartup(result) }()
	defer func() {
		if reason, ok := failure.ReasonOf(result); ok && reason == failure.ServerDenied {
			result = failure.Wrap("authorize service connection", failure.ConnectAccessRequired, result)
		}
	}()
	requestedProtocol := flags.Protocol
	if err := validateConnectMode(flags); err != nil {
		return err
	}
	var options publisherjob.ServiceOptions
	var err error
	if flags.Install {
		options, err = (systemStateFlags{SystemStateDir: flags.SystemStateDir}).options()
		if err != nil {
			return err
		}
		if err := requireInstalledService(ctx, options, nil); err != nil {
			return err
		}
	}
	if flags.Listen != "" {
		flags.Listen, err = connectListen(flags.Listen)
		if err != nil {
			return err
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl connect", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := selectSessionConnectService(ctx, session, flags.project, flags.Name, flags.scopedTeamFlags)
	if err != nil {
		return err
	}
	if err := validateConnectServiceMode(flags, service); err != nil {
		return err
	}
	if flags.Detach {
		if flags.detach == nil {
			return publisherCLIError("detached connector launcher is unavailable")
		}
		return flags.detach()
	}
	if flags.Stdio {
		finishStartup(nil)
		return runConnectStdio(observability.Independent(ctx), session, service, output)
	}
	flags.Protocol = string(service.Protocol)
	if flags.Listen == "" && service.ManagedTls != nil {
		flags.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(service.ManagedTls.Port))
	}
	identity := session.identity.Identity.Id
	jobID := publisherjob.JobKey(session.authenticated.ServerEndpoint, "connect", identity+":"+service.Id)
	var registry *publisherjob.Registry
	listenAddress := ""
	if flags.Install {
		registry, err = publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: true})
		if err != nil {
			return err
		}
		defer registry.Close()
		jobs, err := registry.List(ctx)
		if err != nil {
			return err
		}
		for _, existing := range jobs {
			if existing.ID == jobID && existing.Kind == publisherjob.KindConnector && (flags.Listen == "" || flags.Listen == existing.Target) {
				listenAddress = existing.Target
			}
		}
	}
	var listener net.Listener
	portProtocol := flags.Protocol
	if portProtocol == "http" || portProtocol == "kubernetes" {
		portProtocol = "tcp"
	}
	if flags.Install {
		override := flags.Listen
		if override == "" {
			override = listenAddress
		}
		listenAddress, err = session.store.PrivateServiceListenAddress(ctx, identity, service.Id, portProtocol, override)
		if err != nil {
			return err
		}
	} else if listenAddress == "" {
		if flags.Listen == "" {
			listener, err = session.store.ListenPrivateService(ctx, identity, service.Id, portProtocol)
		} else {
			listener, err = session.store.ListenPrivateServiceAt(ctx, identity, service.Id, flags.Listen)
		}
		if err != nil {
			return err
		}
		defer listener.Close()
		listenAddress = listener.Addr().String()
	}
	job := publisherjob.Job{Kind: publisherjob.KindConnector, ID: jobID, Name: service.Name,
		Server: session.authenticated.ServerEndpoint, PrivateServiceID: service.Id, IdentityID: identity, StateDir: session.database.Root(),
		Protocol: config.ProtocolName(flags.Protocol), Target: listenAddress, TrustRevision: service.TrustRevision}
	job.ManagedTLS = service.ManagedTls
	writeReady := func(job publisherjob.Job, destination io.Writer) error {
		profile, err := serviceConnectionProfile(controlv1.PrivateService{Id: job.PrivateServiceID, Protocol: controlv1.PrivateServiceProtocol(job.Protocol), Enabled: true, ManagedTls: job.ManagedTLS}, job.Target)
		if err != nil {
			return err
		}
		if job.Protocol == config.ProtocolKubernetes {
			if err := prepareKubernetesConnection(ctx, session, flags, service, &profile, job.Target); err != nil {
				return err
			}
		}
		detachedConnectorPrepared(ctx, profile)
		return writeNativeConnection(destination, profile, flags.Output, job.Target)
	}
	if flags.Install {
		if err := registry.InstallConnector(ctx, job); err != nil {
			return err
		}
		if err := waitInstalledConnectorReady(ctx, registry, job.ID); err != nil {
			return err
		}
		return writeReady(job, output)
	}
	return runPrivateConnectorLifecycle(observability.Independent(ctx), listener, job, requestedProtocol, privateConnectorLifecycle{
		services: session.authenticated.Control,
		listen: func(ctx context.Context, job publisherjob.Job) (net.Listener, error) {
			return session.store.ListenPrivateServiceAt(ctx, job.IdentityID, job.PrivateServiceID, job.Target)
		},
		serve: func(ctx context.Context, listener net.Listener, job publisherjob.Job, ready func() error) error {
			return servePrivateConnector(ctx, session, listener, job, ready)
		},
		ready: func(job publisherjob.Job) error {
			finishStartup(nil)
			if flags.Output == statusOutputJSON {
				return writeReady(job, output)
			}
			return writeReady(job, diagnostics)
		},
	})
}

func selectSessionConnectService(ctx context.Context, session *teamSession, project projectConfiguration, name string, flags scopedTeamFlags) (controlv1.PrivateService, error) {
	key, err := configuredConnectService(project, name)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	team := ""
	if flags.Team != "" || flags.ProjectTeam != "" || key != "" {
		membership, err := session.currentMembership(ctx)
		if err != nil {
			return controlv1.PrivateService{}, err
		}
		team = membership.TeamId
	}
	return selectConnectService(ctx, session.authenticated.Control, project, name, team)
}

type privateConnectorLifecycle struct {
	services connectInventoryReader
	listen   func(context.Context, publisherjob.Job) (net.Listener, error)
	serve    func(context.Context, net.Listener, publisherjob.Job, func() error) error
	ready    func(publisherjob.Job) error
}

// Serve joins its streams, paths and assignment owner before returning. only its
// metadata boundary can reopen this exact reserved port in the same process.
// installed connectors already refresh through the supervisor's job attempts.
func runPrivateConnectorLifecycle(ctx context.Context, listener net.Listener, job publisherjob.Job, requestedProtocol string, lifecycle privateConnectorLifecycle) error {
	for {
		detachedPublicationStarting(ctx)
		err := lifecycle.serve(ctx, listener, job, func() error {
			if err := lifecycle.ready(job); err != nil {
				return err
			}
			detachedPublicationReady(ctx)
			return nil
		})
		_ = listener.Close()
		if !tcpconnect.IsMetadataReload(err) {
			return err
		}
		detachedPublicationStarting(ctx)
		if ctx.Err() != nil {
			return nil
		}
		services, err := lifecycle.services.ListAvailablePrivateServices(ctx)
		if err != nil {
			return err
		}
		service, err := privateServiceIDSelection(services, job.PrivateServiceID, "")
		if err != nil {
			return err
		}
		if requestedProtocol != "" && requestedProtocol != string(service.Protocol) {
			return connectModeError(failure.ConnectProtocolMismatch)
		}
		job.Trust = nil
		job.Name, job.Protocol, job.TrustRevision = service.Name, config.ProtocolName(service.Protocol), service.TrustRevision
		job.ManagedTLS = service.ManagedTls
		listener, err = lifecycle.listen(ctx, job)
		if err != nil {
			return err
		}
	}
}

func servePrivateConnector(ctx context.Context, session *teamSession, listener net.Listener, job publisherjob.Job, ready func() error) error {
	configuration, err := connectConfiguration(ctx, session, job)
	if err != nil {
		return err
	}
	configuration.Ready = ready
	return tcpconnect.Serve(ctx, listener, configuration)
}

func connectConfiguration(ctx context.Context, session *teamSession, job publisherjob.Job) (tcpconnect.Config, error) {
	control, err := tcpconnect.NewControl(session.authenticated.Control, session.store, job.IdentityID)
	if err != nil {
		return tcpconnect.Config{}, err
	}
	var serviceTLS *tls.Config
	if job.ManagedTLS != nil {
		serviceTLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: job.ManagedTLS.Hostname}
	}
	return tcpconnect.Config{Control: control, PrivateServiceID: job.PrivateServiceID,
		IdentityID: job.IdentityID, Protocol: string(job.Protocol), TrustRevision: job.TrustRevision, ManagedTLS: job.ManagedTLS, ServiceTLS: serviceTLS}, nil
}

func waitInstalledConnectorReady(ctx context.Context, registry *publisherjob.Registry, id string) error {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		jobs, err := registry.List(bounded)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if job.ID == id && job.Status.State == "ready" {
				return nil
			}
		}
		select {
		case <-bounded.Done():
			return failure.Wrap("wait for installed connector", failure.ConnectionUnavailable, context.Cause(bounded))
		case <-tick.C:
		}
	}
}

func runInstalledConnector(ctx context.Context, job publisherjob.Job, ready func() error) error {
	session, err := openTeamSession(ctx, remoteFlags{ServerURL: job.Server, StateDir: job.StateDir}, "tnl connect", io.Discard)
	if err != nil {
		return err
	}
	defer session.Close()
	if session.identity.Identity.Id != job.IdentityID {
		return publisherCLIError("connector sign-in identity changed; remove and install it for the current identity")
	}
	services, err := session.authenticated.Control.ListAvailablePrivateServices(ctx)
	if err != nil {
		return err
	}
	service, err := privateServiceIDSelection(services, job.PrivateServiceID, "")
	if err != nil {
		return err
	}
	if err := validateConnectServiceMode(connectStartCommand{Install: true}, service); err != nil {
		return err
	}
	job.Protocol = config.ProtocolName(service.Protocol)
	job.Trust = nil
	job.TrustRevision = service.TrustRevision
	job.ManagedTLS = service.ManagedTls
	listener, err := session.store.ListenPrivateServiceAt(ctx, job.IdentityID, job.PrivateServiceID, job.Target)
	if err != nil {
		return err
	}
	defer listener.Close()
	return servePrivateConnector(ctx, session, listener, job, ready)
}

func runConnectJobs(ctx context.Context, flags connectListCommand, name, action string, output io.Writer) error {
	options, err := (systemStateFlags{SystemStateDir: flags.SystemStateDir}).options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: true})
	if err != nil {
		return err
	}
	defer registry.Close()
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	connectors := []publisherjob.Job{}
	for _, job := range jobs {
		if job.Kind == "connector" && (name == "" || job.Name == name || job.ID == name) {
			connectors = append(connectors, job)
		}
	}
	if name != "" {
		if len(connectors) == 0 {
			return publisherjob.ErrJobNotFound
		}
		if len(connectors) != 1 {
			return publisherjob.ErrJobAmbiguous
		}
		job := connectors[0]
		if err := registry.Stop(ctx, job.ID); err != nil {
			return err
		}
		if action == "remove" {
			wait, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			if err := registry.WaitStopped(wait, job.ID); err != nil {
				return err
			}
			if err := registry.Remove(ctx, job.ID); err != nil {
				return err
			}
			database, err := clientstate.Open(ctx, job.StateDir)
			if err != nil {
				return err
			}
			defer database.Close()
			profile, err := database.Server(ctx, job.Server)
			if err != nil {
				return err
			}
			if err := profile.RemovePrivateServicePort(ctx, job.IdentityID, job.PrivateServiceID); err != nil {
				return err
			}
			return writeHumanFrame(output, "tnl connect remove", "removed", "", clioutput.Fields(clioutput.Field{Label: "name", Value: job.Name}))
		}
		return writeSystemJobs(ctx, registry, output, "tnl connect stop", job.ID)
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(connectors)
	}
	return renderSystemJobs(output, "tnl connect "+strings.TrimSpace(action), connectors, "")
}

type connectAvailableCommand struct {
	remoteFlags `embed:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runConnectAvailable(ctx context.Context, command connectAvailableCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl connect available", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	services, err := session.authenticated.Control.ListAvailablePrivateServices(ctx)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		if services == nil {
			services = []controlv1.PrivateService{}
		}
		return json.NewEncoder(output).Encode(services)
	}
	blocks := make([]clioutput.Block, 0, len(services))
	for _, service := range services {
		state := "offline"
		if service.Enabled && service.PrivateRunId != nil && service.RunNumber != nil {
			state = "ready"
		}
		blocks = append(blocks, clioutput.Section(service.Name, clioutput.Fields(
			clioutput.Field{Label: "private service ID", Value: service.Id},
			clioutput.Field{Label: "team ID", Value: service.TeamId},
			clioutput.Field{Label: "state", Value: state},
		)))
	}
	return writeHumanFrame(output, "tnl connect available", countState(len(services), "private service", "private services"), "", blocks...)
}
