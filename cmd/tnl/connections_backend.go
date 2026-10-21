package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/kubeconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/internal/workloadclient"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type preparedConnection struct {
	service    controlv1.PrivateService
	connection connectionruntime.Connection
	kubeSource kubeconfig.Source
	kubePlan   kubeconfig.Plan
	kubeResult kubeconfig.Result
}

type nativeConnectionBackend struct {
	project                                                projectConfiguration
	scope                                                  connectionruntime.Context
	stateDir, assertion, directory, executable, runnerTemp string
	human                                                  *teamSession
	workload                                               *workloadclient.Client
	deadline                                               time.Time
	prepared                                               map[string]*preparedConnection
	cancel                                                 context.CancelFunc
	workers                                                sync.WaitGroup
	mu                                                     sync.Mutex
	err                                                    error
	cleanupErr                                             error
	failed                                                 chan error
	failOnce                                               sync.Once
	parentPID                                              int
	kubeOptions                                            connectStartCommand
	sessionKubePlan                                        kubeconfig.Plan
	sessionKubeResult                                      kubeconfig.Result
}

func (b *nativeConnectionBackend) Start(ctx context.Context) (projectmeta.PublicMetadata, time.Time, error) {
	b.prepared = map[string]*preparedConnection{}
	b.failed = make(chan error, 1)
	lifetime, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Services: map[string]projectmeta.Service{}}
	services := map[string]controlv1.PrivateService{}
	if b.scope.CI != "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		client, err := workloadclient.NewWithKey(b.scope.Server, nil, key)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.workload = client
		session, err := exchangeConnectionWorkload(ctx, client, b.scope, b.assertion)
		b.assertion = "" // neither the assertion nor GitHub's request bearer survives exchange.
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.deadline = session.ExpiresAt
		if session.ExpiresAt.After(time.Now().Add(b.project.Config.CI[b.scope.CI].DurationLimit())) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrExpired
		}
		inventory, err := client.ListServices(ctx)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		for _, service := range inventory.Services {
			if _, duplicate := services[service.Service]; duplicate {
				return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrInvalid
			}
			services[service.Service] = controlv1.PrivateService{Id: service.Id, Name: service.Service, TeamId: b.scope.TeamID, Protocol: service.Protocol, Enabled: true, ManagedTls: &service.ManagedTls, KubernetesAuth: service.KubernetesAuth}
		}
	} else {
		session, err := openTeamSession(ctx, remoteFlags{ServerURL: b.scope.Server, StateDir: b.stateDir, ProjectTeam: b.scope.TeamID}, "tnl connect", io.Discard)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.human = session
		b.deadline = time.Now().Add(time.Hour)
		membership, err := session.currentMembership(ctx)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.scope.TeamID = membership.TeamId
		for _, name := range b.scope.Services {
			service, err := selectConnectService(ctx, session.authenticated.Control, b.project, name, membership.TeamId)
			if err != nil {
				return projectmeta.PublicMetadata{}, time.Time{}, err
			}
			services[name] = service
		}
	}
	for _, name := range b.scope.Services {
		service, ok := services[name]
		if !ok {
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrUnavailable
		}
		if err := validateProfileService(service); err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		endpoint := service.ManagedTls
		if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrInvalid
		}
		connection := connectionruntime.Connection{Schema: 1, Protocol: string(service.Protocol), Host: "127.0.0.1", Port: endpoint.Port, ExpiresAt: b.deadline}
		p := &preparedConnection{service: service, connection: connection}
		b.prepared[name] = p
		verification := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname}
		var control tcpconnect.Control
		var err error
		identity := ""
		if b.workload != nil {
			control, err = tcpconnect.NewWorkloadControl(b.workload)
		} else {
			identity = b.human.identity.Identity.Id
			control, err = tcpconnect.NewControl(b.human.authenticated.Control, b.human.store, identity)
		}
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		run, err := control.ResolvePrivateService(ctx, service.Id)
		if err != nil {
			if closer, ok := control.(io.Closer); ok {
				_ = closer.Close()
			}
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		if run.Protocol != string(service.Protocol) || run.ManagedTLS == nil || *run.ManagedTLS != *endpoint {
			if closer, ok := control.(io.Closer); ok {
				_ = closer.Close()
			}
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrUnavailable
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(endpoint.Port)))
		if err != nil {
			if closer, ok := control.(io.Closer); ok {
				_ = closer.Close()
			}
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		ready := make(chan struct{})
		done := make(chan error, 1)
		connection.Port = listener.Addr().(*net.TCPAddr).Port
		configuration := tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: identity, Protocol: string(service.Protocol), TrustRevision: run.TrustRevision, ManagedTLS: endpoint, ServiceTLS: verification, Ready: func() error { close(ready); return nil }}
		b.workers.Go(func() {
			defer listener.Close()
			err := tcpconnect.Serve(lifetime, listener, configuration)
			b.mu.Lock()
			if lifetime.Err() == nil {
				b.err = errors.Join(connectionruntime.ErrUnavailable, err)
				b.failOnce.Do(func() { b.failed <- b.err })
			} else if err != nil && err != context.Canceled {
				b.cleanupErr = errors.Join(b.cleanupErr, err)
			}
			b.mu.Unlock()
			done <- err
		})
		select {
		case <-ready:
		case err := <-done:
			return projectmeta.PublicMetadata{}, time.Time{}, errors.Join(connectionruntime.ErrUnavailable, err)
		case <-ctx.Done():
			return projectmeta.PublicMetadata{}, time.Time{}, ctx.Err()
		}
		p.connection = connection
		if string(service.Protocol) == "http" || string(service.Protocol) == "kubernetes" {
			p.connection.URL = "https://" + net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port))
		}
		if string(service.Protocol) == "kubernetes" {
			if err := b.prepareKube(ctx, name, p); err != nil {
				return projectmeta.PublicMetadata{}, time.Time{}, err
			}
		}
		value, err := projectmeta.NewEndpoint(endpoint.Hostname, endpoint.Hostname, string(service.Protocol), endpoint.Port, endpoint.Public)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		metadata.Services[name] = value
		if metadata.Namespace == "" {
			metadata.Namespace = endpoint.Hostname
		}
	}
	if err := metadata.Validate(); err != nil {
		return projectmeta.PublicMetadata{}, time.Time{}, err
	}
	return metadata.Public(false), b.deadline, nil
}

// a lost exchange response must retry the same assertion and in-memory key.
// a replacement owner/key cannot take over an already committed execution.
func exchangeConnectionWorkload(ctx context.Context, client *workloadclient.Client, scope connectionruntime.Context, assertion string) (authorityv1.WorkloadSession, error) {
	var session authorityv1.WorkloadSession
	var err error
	for attempt := range 3 {
		session, err = client.Exchange(ctx, scope.TeamID, scope.ProjectKey, scope.CI, assertion, scope.Services)
		if err == nil {
			return session, nil
		}
		_, definition, known := failure.Describe(err)
		if !known || definition.Retry != failure.RetryLater || attempt == 2 || ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return authorityv1.WorkloadSession{}, ctx.Err()
		case <-timer.C:
		}
	}
	return session, err
}

func (b *nativeConnectionBackend) Connect(ctx context.Context, name string) (connectionruntime.Connection, error) {
	if _, err := b.healthy(); err != nil {
		return connectionruntime.Connection{}, err
	}
	p := b.prepared[name]
	if p == nil {
		return connectionruntime.Connection{}, connectionruntime.ErrInvalid
	}
	result := p.connection
	if p.service.Protocol != controlv1.Tcp {
		options := connectionruntime.TLSOptions{ServerName: p.service.ManagedTls.Hostname, RejectUnauthorized: true}
		result.SSL = &options
	}
	return result, nil
}
func (b *nativeConnectionBackend) healthy() (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return time.Time{}, b.err
	}
	if !b.deadline.After(time.Now()) {
		return time.Time{}, connectionruntime.ErrExpired
	}
	return b.deadline, nil
}
func (b *nativeConnectionBackend) Renew(ctx context.Context) (time.Time, error) {
	if b.scope.CI == "" && b.parentPID > 0 {
		process, err := os.FindProcess(b.parentPID)
		if err != nil || process.Signal(syscall.Signal(0)) != nil {
			return time.Time{}, connectionruntime.ErrExpired
		}
	}
	if _, err := b.healthy(); err != nil {
		return time.Time{}, err
	}
	if b.workload != nil {
		session, err := b.workload.Renew(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if !session.ExpiresAt.Equal(b.deadline) || !session.LeaseExpiresAt.After(time.Now()) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
			return time.Time{}, connectionruntime.ErrExpired
		}
		for _, p := range b.prepared {
			if !slices.Contains(session.ServiceIds, p.service.Id) {
				return time.Time{}, connectionruntime.ErrUnavailable
			}
		}
		return session.ExpiresAt, nil
	}
	return b.deadline, nil
}
func (b *nativeConnectionBackend) Done() <-chan error { return b.failed }
func (b *nativeConnectionBackend) Kubeconfig() string {
	for _, p := range b.prepared {
		if p.connection.Kubeconfig != "" {
			return p.connection.Kubeconfig
		}
	}
	return ""
}
func (b *nativeConnectionBackend) Close(ctx context.Context) (result error) {
	if b.cancel != nil {
		b.cancel()
	}
	b.workers.Wait()
	result = errors.Join(result, b.cleanupErr)
	if b.sessionKubeResult.File != "" {
		result = errors.Join(result, b.sessionKubePlan.CleanupSession(ctx, b.sessionKubeResult))
	}
	if b.workload != nil {
		if _, err := b.workload.Session(); err == nil {
			result = errors.Join(result, b.workload.Revoke(ctx))
		}
	}
	if b.human != nil {
		result = errors.Join(result, b.human.Close())
	}
	return result
}

func (b *nativeConnectionBackend) prepareKube(ctx context.Context, name string, p *preparedConnection) error {
	p.kubeSource = kubeconfig.Source{TokenFile: b.kubeOptions.KubeTokenFile, ConfigFile: b.kubeOptions.KubeUserConfig, ExistingUser: b.kubeOptions.KubeUser}
	var err error
	if p.kubeSource.TokenFile != "" {
		p.kubeSource.TokenFile, err = filepath.Abs(p.kubeSource.TokenFile)
		if err != nil {
			return err
		}
	}
	if p.kubeSource.ConfigFile != "" {
		p.kubeSource.ConfigFile, err = filepath.Abs(p.kubeSource.ConfigFile)
		if err != nil {
			return err
		}
	}
	if p.kubeSource.TokenFile == "" && p.kubeSource.ConfigFile == "" && p.kubeSource.ExistingUser == "" && p.service.KubernetesAuth != nil {
		hint := p.service.KubernetesAuth
		if hint.Provider != controlv1.KubernetesEKS {
			return kubeconfig.ErrCredential
		}
		p.kubeSource.EKS = &kubeconfig.EKS{Cluster: hint.Cluster, Region: hint.Region}
	}
	if err := p.kubeSource.Validate(); err != nil {
		return err
	}
	if b.scope.CI != "" {
		if b.sessionKubePlan.Path == "" {
			b.sessionKubePlan, err = kubeconfig.PlanSession(b.directory, "session")
		}
		p.kubePlan = b.sessionKubePlan
		if b.sessionKubeResult.File != "" {
			p.kubePlan.Exclusive = false
		}
	} else {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return homeErr
		}
		p.kubePlan, err = kubeconfig.PlanLocal(home, os.Getenv("KUBECONFIG"))
	}
	if err != nil {
		return err
	}
	owner := kubeconfig.Owner{ControlURL: b.scope.Server, TeamID: b.scope.TeamID, SourceID: b.scope.SourceID, ServiceID: p.service.Id}
	p.kubeResult, err = p.kubePlan.Prepare(ctx, kubeconfig.Options{Owner: owner, ProjectLabel: b.scope.ProjectLabel, Service: name, Namespace: b.kubeOptions.Namespace, Server: "https://" + net.JoinHostPort(p.connection.Host, strconv.Itoa(p.connection.Port)), TLSServerName: p.service.ManagedTls.Hostname, Helper: b.executable, Profile: filepath.Join(b.directory, "handle.json"), CredentialArgs: []string{"runtime", "connections", "kube-credential", "--handle", filepath.Join(b.directory, "handle.json"), "--service", name}})
	if err == nil {
		if b.scope.CI != "" {
			b.sessionKubeResult = p.kubeResult
		}
		p.connection.Kubeconfig = p.kubeResult.File
		p.connection.Context = p.kubeResult.Context
	}
	return err
}

func (b *nativeConnectionBackend) Credential(ctx context.Context, name string) (credentialv1.ExecCredential, error) {
	p := b.prepared[name]
	if p == nil || p.connection.Protocol != "kubernetes" {
		return credentialv1.ExecCredential{}, kubeconfig.ErrCredential
	}
	credential, err := kubeconfig.Credential(ctx, kubeconfig.Profile{Source: p.kubeSource}, nil)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	connection, err := b.Connect(ctx, name)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	if credential.Status.ExpirationTimestamp == nil || credential.Status.ExpirationTimestamp.Time.After(connection.ExpiresAt) {
		credential.Status.ExpirationTimestamp = &metav1.Time{Time: connection.ExpiresAt}
	}
	return credential, nil
}
