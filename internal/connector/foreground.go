package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/region"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type StartOptions struct {
	SessionOptions
	Team                                                           string
	Name, Listen, Protocol                                         string
	PreferredRegions                                               []string
	Kubeconfig, Namespace, KubeUserConfig, KubeUser, KubeTokenFile string
	Foreground, Detach, Install, System, Stdio                     bool
	SystemStateDir, DetachedChild, Output                          string
	Project                                                        clientproject.Project
	project                                                        projectConfiguration
	DetachLaunch                                                   func() error
	Ready                                                          func(io.Writer, Profile, string) error
	Starting                                                       func(context.Context)
	PublicationReady                                               func(context.Context)
	Prepared                                                       func(context.Context, Profile)
	ServiceOptions                                                 supervisor.ServiceOptions
}

func ValidateMode(flags StartOptions) error {
	if _, err := region.Preferences(flags.PreferredRegions); err != nil {
		return publisherCLIError("--prefer-region requires distinct known tnl or provider regions")
	}
	if flags.Stdio && (flags.Listen != "" || flags.Install || flags.Detach || flags.Foreground || flags.DetachedChild != "" || flags.Output == "json") {
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

func ValidateServiceMode(flags StartOptions, service controlv1.Service) error {
	if err := ValidateService(service); err != nil {
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

func (o Operations) Start(ctx context.Context, flags StartOptions, input *os.File, output, diagnostics io.Writer) (result error) {
	flags.project = projectConfiguration{Project: flags.Project}
	ctx, finishStartup := observability.ClientOperation(ctx, "client.connect.startup")
	defer func() { finishStartup(result) }()
	defer func() {
		if reason, ok := failure.ReasonOf(result); ok && reason == failure.ServerDenied {
			result = failure.Wrap("authorize service connection", failure.ConnectAccessRequired, result)
		}
	}()
	requestedProtocol := flags.Protocol
	if err := ValidateMode(flags); err != nil {
		return err
	}
	options := flags.ServiceOptions
	var err error
	if flags.Listen != "" {
		flags.Listen, err = connectListen(flags.Listen)
		if err != nil {
			return err
		}
	}
	session, err := o.OpenSession(ctx, flags.SessionOptions, "tnl connect", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := selectSessionConnectService(ctx, session, flags.project, flags.Name, flags)
	if err != nil {
		return err
	}
	if err := ValidateServiceMode(flags, service); err != nil {
		return err
	}
	if flags.Detach {
		if flags.DetachLaunch == nil {
			return publisherCLIError("detached connector launcher is unavailable")
		}
		return flags.DetachLaunch()
	}
	if flags.Stdio {
		finishStartup(nil)
		return runConnectStdio(observability.Independent(ctx), session, service, input, output, flags.PreferredRegions...)
	}
	flags.Protocol = string(service.Protocol)
	if flags.Listen == "" && service.Endpoint != nil {
		flags.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(service.Endpoint.Port))
	}
	identity := session.identity.Identity.Id
	jobID := supervisor.JobKey(session.authenticated.ServerEndpoint, "connect", identity+":"+service.Id)
	var registry *supervisor.Registry
	listenAddress := ""
	if flags.Install {
		registry, err = supervisor.Open(ctx, supervisor.OpenOptions{Root: options.Root, User: true})
		if err != nil {
			return err
		}
		defer registry.Close()
		jobs, err := registry.List(ctx)
		if err != nil {
			return err
		}
		for _, existing := range jobs {
			if existing.ID == jobID && existing.Kind == supervisor.KindConnector && (flags.Listen == "" || flags.Listen == existing.Target) {
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
		listenAddress, err = session.store.ServiceListenAddress(ctx, identity, service.Id, portProtocol, override)
		if err != nil {
			return err
		}
	} else if listenAddress == "" {
		if flags.Listen == "" {
			listener, err = session.store.ListenService(ctx, identity, service.Id, portProtocol)
		} else {
			listener, err = session.store.ListenServiceAt(ctx, identity, service.Id, flags.Listen)
		}
		if err != nil {
			return err
		}
		defer listener.Close()
		listenAddress = listener.Addr().String()
	}
	job := supervisor.Job{Kind: supervisor.KindConnector, ID: jobID, Name: service.Name,
		Server: session.authenticated.ServerEndpoint, ServiceID: service.Id, IdentityID: identity, StateDir: session.database.Root(),
		Protocol: config.ProtocolName(flags.Protocol), Target: listenAddress, TrustRevision: service.TrustRevision, PreferredRegions: append([]string(nil), flags.PreferredRegions...)}
	job.Endpoint = service.Endpoint
	writeReady := func(job supervisor.Job, destination io.Writer) error {
		profile, err := serviceConnectionProfile(controlv1.Service{Id: job.ServiceID, Protocol: controlv1.ServiceProtocol(job.Protocol), Enabled: true, Endpoint: job.Endpoint}, job.Target)
		if err != nil {
			return err
		}
		if job.Protocol == config.ProtocolKubernetes {
			if err := prepareKubernetesConnection(ctx, session, flags, service, &profile, job.Target); err != nil {
				return err
			}
		}
		if flags.Prepared != nil {
			flags.Prepared(ctx, profile)
		}
		return flags.Ready(destination, profile, job.Target)
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
	return runConnectorLifecycle(observability.Independent(ctx), listener, job, requestedProtocol, connectorLifecycle{
		starting:         flags.Starting,
		publicationReady: flags.PublicationReady,
		services:         session.authenticated.Control,
		listen: func(ctx context.Context, job supervisor.Job) (net.Listener, error) {
			return session.store.ListenServiceAt(ctx, job.IdentityID, job.ServiceID, job.Target)
		},
		serve: func(ctx context.Context, listener net.Listener, job supervisor.Job, ready func() error) error {
			return serveConnector(ctx, session, listener, job, ready)
		},
		ready: func(job supervisor.Job) error {
			finishStartup(nil)
			if flags.Output == "json" {
				return writeReady(job, output)
			}
			return writeReady(job, diagnostics)
		},
	})
}

func selectSessionConnectService(ctx context.Context, session *Session, project projectConfiguration, name string, flags StartOptions) (controlv1.Service, error) {
	key, err := ConfiguredService(project.Project, name)
	if err != nil {
		return controlv1.Service{}, err
	}
	team := ""
	if flags.Team != "" || flags.ProjectTeam != "" || key != "" {
		membership, err := session.currentMembership(ctx)
		if err != nil {
			return controlv1.Service{}, err
		}
		team = membership.TeamId
	}
	return Select(ctx, session.authenticated.Control, project.Project, name, team)
}

type connectorLifecycle struct {
	starting         func(context.Context)
	publicationReady func(context.Context)
	services         connectInventoryReader
	listen           func(context.Context, supervisor.Job) (net.Listener, error)
	serve            func(context.Context, net.Listener, supervisor.Job, func() error) error
	ready            func(supervisor.Job) error
}

// Serve joins its streams, paths and assignment owner before returning. only its
// metadata boundary can reopen this exact reserved port in the same process.
// installed connectors already refresh through the supervisor's job attempts.
func runConnectorLifecycle(ctx context.Context, listener net.Listener, job supervisor.Job, requestedProtocol string, lifecycle connectorLifecycle) error {
	recovering := false
	for {
		if lifecycle.starting != nil {
			lifecycle.starting(ctx)
		}
		err := lifecycle.serve(ctx, listener, job, func() error {
			if err := lifecycle.ready(job); err != nil {
				return err
			}
			recovering = false
			if lifecycle.publicationReady != nil {
				lifecycle.publicationReady(ctx)
			}
			return nil
		})
		_ = listener.Close()
		if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil
		}
		if errors.Is(err, connectorstream.ErrSelectionExpired) {
			recovering = true
		} else if recovering && (errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded)) {
			// a previously verified publisher may still be replacing its run.
			// a bounded preparation timeout does not invalidate the service.
		} else if !connectorstream.IsMetadataReload(err) {
			return err
		}
		if lifecycle.starting != nil {
			lifecycle.starting(ctx)
		}
		if ctx.Err() != nil {
			return nil
		}
		var services []controlv1.Service
		for {
			var err error
			services, err = lifecycle.services.ListAvailableServices(ctx)
			if err == nil {
				break
			}
			if !recovering || !errors.Is(err, clientcontrol.ErrUnavailable) {
				return err
			}
			if err := waitConnectorRecovery(ctx); err != nil {
				return err
			}
		}
		service, err := serviceIDSelection(services, job.ServiceID, "")
		if err != nil {
			return err
		}
		if requestedProtocol != "" && requestedProtocol != string(service.Protocol) {
			return connectModeError(failure.ConnectProtocolMismatch)
		}
		job.Trust = nil
		job.Name, job.Protocol, job.TrustRevision = service.Name, config.ProtocolName(service.Protocol), service.TrustRevision
		job.Endpoint = service.Endpoint
		if recovering {
			if err := waitConnectorRecovery(ctx); err != nil {
				return err
			}
		}
		listener, err = lifecycle.listen(ctx, job)
		if err != nil {
			return err
		}
	}
}

func waitConnectorRecovery(ctx context.Context) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func serveConnector(ctx context.Context, session *Session, listener net.Listener, job supervisor.Job, ready func() error) error {
	configuration, err := connectConfiguration(ctx, session, job)
	if err != nil {
		return err
	}
	configuration.Ready = ready
	return connectorstream.Serve(ctx, listener, configuration)
}

func connectConfiguration(ctx context.Context, session *Session, job supervisor.Job) (connectorstream.Config, error) {
	control, err := connectorstream.NewControl(session.authenticated.Control, session.store, job.IdentityID, job.PreferredRegions...)
	if err != nil {
		return connectorstream.Config{}, err
	}
	var serviceTLS *tls.Config
	if job.Endpoint != nil {
		serviceTLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: job.Endpoint.Hostname}
	}
	return connectorstream.Config{Control: control, ServiceID: job.ServiceID,
		IdentityID: job.IdentityID, Protocol: string(job.Protocol), TrustRevision: job.TrustRevision, Endpoint: job.Endpoint, ServiceTLS: serviceTLS}, nil
}

func waitInstalledConnectorReady(ctx context.Context, registry *supervisor.Registry, id string) error {
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

func (o Operations) RunInstalled(ctx context.Context, job supervisor.Job, ready func() error) error {
	session, err := o.OpenSession(ctx, SessionOptions{ServerURL: job.Server, StateDir: job.StateDir}, "tnl connect", io.Discard)
	if err != nil {
		return err
	}
	defer session.Close()
	if session.identity.Identity.Id != job.IdentityID {
		return publisherCLIError("connector sign-in identity changed; remove and install it for the current identity")
	}
	services, err := session.authenticated.Control.ListAvailableServices(ctx)
	if err != nil {
		return err
	}
	service, err := serviceIDSelection(services, job.ServiceID, "")
	if err != nil {
		return err
	}
	if err := ValidateServiceMode(StartOptions{Install: true}, service); err != nil {
		return err
	}
	job.Protocol = config.ProtocolName(service.Protocol)
	job.Trust = nil
	job.TrustRevision = service.TrustRevision
	job.Endpoint = service.Endpoint
	listener, err := session.store.ListenServiceAt(ctx, job.IdentityID, job.ServiceID, job.Target)
	if err != nil {
		return err
	}
	defer listener.Close()
	return serveConnector(ctx, session, listener, job, ready)
}
