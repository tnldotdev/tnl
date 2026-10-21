package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
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
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/internal/workloadclient"
	"github.com/tnldotdev/tnl/internal/workloadmanifest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type preparedConnection struct {
	service         controlv1.PrivateService
	connection      connectionruntime.Connection
	kubeSource      kubeconfig.Source
	kubePlan        kubeconfig.Plan
	kubeResult      kubeconfig.Result
	err             error
	listener        *connectionruntime.ListenerSwitch
	epoch           int
	ready           bool
	cancel          context.CancelFunc
	control         tcpconnect.Control
	authorizedUntil time.Time
	sessionID       string
}

type nativeConnectionBackend struct {
	project                                                projectConfiguration
	scope                                                  connectionruntime.Context
	stateDir, assertion, directory, executable, runnerTemp string
	human                                                  *teamSession
	workload                                               *workloadclient.Client
	httpClient                                             *http.Client
	replacement                                            *workloadclient.Client
	replacementScope                                       connectionruntime.Context
	acquisition                                            workloadmanifest.Acquisition
	deadline                                               time.Time
	prepared                                               map[string]*preparedConnection
	initialServices                                        []string
	services                                               map[string]controlv1.PrivateService
	metadata                                               projectmeta.PublicMetadata
	lifetime                                               context.Context
	prepareMu                                              sync.Mutex
	cancel                                                 context.CancelFunc
	workers                                                sync.WaitGroup
	mu                                                     sync.Mutex
	cleanupErr                                             error
	parentPID                                              int
	kubeOptions                                            connectStartCommand
	verification                                           *connectionruntime.AssertionVerification
	assertions                                             map[string]connectionruntime.AssertionVerification
	assertionChecks                                        map[string]time.Time
	verifiedSession                                        string
	sessionKubePlan                                        kubeconfig.Plan
	sessionKubeResult                                      kubeconfig.Result
}

func (b *nativeConnectionBackend) Start(ctx context.Context) (projectmeta.PublicMetadata, time.Time, error) {
	b.prepared = map[string]*preparedConnection{}
	lifetime, cancel := context.WithCancel(observability.Independent(context.WithoutCancel(ctx)))
	b.cancel = cancel
	b.lifetime = lifetime
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Services: map[string]projectmeta.Service{}}
	services := map[string]controlv1.PrivateService{}
	if b.scope.Workload != "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		client, err := workloadclient.NewWithKey(b.scope.Server, b.httpClient, key)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.workload = client
		identity, err := client.IdentifyPolicy(ctx, b.scope.TeamID, b.scope.ProjectKey, b.scope.SourceID, b.scope.Workload, b.assertion)
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		selected := []string{}
		for _, name := range b.scope.Services {
			if slices.Contains(identity.Services, name) {
				selected = append(selected, name)
			}
		}
		if len(selected) == 0 {
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrUnauthorized
		}
		requested := b.scope
		requested.Services = selected
		assertion := b.assertion
		session, err := exchangeConnectionWorkload(ctx, client, requested, assertion)
		b.assertion = "" // neither the assertion nor GitHub's request bearer survives exchange.
		if err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
		b.deadline = session.ExpiresAt
		if session.Binding != identity.Binding {
			return projectmeta.PublicMetadata{}, time.Time{}, connectionruntime.ErrUnauthorized
		}
		b.rememberAssertion(assertion, identity.AssertionExpiresAt, session)
		if session.ExpiresAt.After(time.Now().Add(b.project.Config.Workloads[b.scope.Workload].DurationLimit())) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
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
			services[service.Service] = controlv1.PrivateService{Id: service.Id, Name: service.Service, TeamId: session.TeamId, Protocol: service.Protocol, Enabled: true, ManagedTls: &service.ManagedTls, KubernetesAuth: service.KubernetesAuth}
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
				continue // one service's denial does not prevent another service's preparation.
			}
			services[name] = service
		}
	}
	for _, name := range b.scope.Services {
		service, ok := services[name]
		if !ok {
			continue
		}
		if err := validateProfileService(service); err != nil {
			delete(services, name)
			continue
		}
		endpoint := service.ManagedTls
		if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
			delete(services, name)
			continue
		}
		value, err := projectmeta.NewEndpoint(endpoint.Hostname, endpoint.Hostname, string(service.Protocol), endpoint.Port, endpoint.Public)
		if err != nil {
			delete(services, name)
			continue
		}
		metadata.Services[name] = value
		if metadata.Namespace == "" {
			metadata.Namespace = endpoint.Hostname
		}
	}
	if err := metadata.Validate(); err != nil {
		return projectmeta.PublicMetadata{}, time.Time{}, err
	}
	b.services = services
	b.metadata = metadata.Public(false)
	// caller-prepared CLI owners retain their aggregate readiness contract.
	// application-owned SDK processes prepare each service on its own IPC read.
	for _, name := range b.initialServices {
		if _, err := b.Connect(ctx, name); err != nil {
			return projectmeta.PublicMetadata{}, time.Time{}, err
		}
	}
	return b.metadata, b.deadline, nil
}

// preparation is incremental and failure is local to the requested service.
// the exchanged service-ID snapshot is independent of this listener map.
func (b *nativeConnectionBackend) prepareService(ctx context.Context, name string, p *preparedConnection) (*preparedConnection, error) {
	service, ok := b.services[name]
	if !ok || !slices.Contains(b.scope.Services, name) {
		return nil, connectionruntime.ErrUnavailable
	}
	if err := validateProfileService(service); err != nil {
		return nil, err
	}
	if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return nil, connectionruntime.ErrInvalid
	}
	endpoint := service.ManagedTls
	b.mu.Lock()
	deadline := b.deadline
	b.mu.Unlock()
	connection := connectionruntime.Connection{Schema: 1, Protocol: string(service.Protocol), Host: "127.0.0.1", Port: endpoint.Port, ExpiresAt: deadline}
	transportID, err := opaqueid.New("ctg_")
	if err != nil {
		return nil, err
	}
	connection.TransportID = transportID
	if p == nil {
		p = &preparedConnection{service: service, connection: connection}
	}
	p.service = service
	verification := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname}
	var control tcpconnect.Control
	// each new adapter receives a fresh transport ID even when its listener stays.
	identity := ""
	if b.workload != nil {
		control, err = tcpconnect.NewWorkloadControl(b.workload)
	} else {
		identity = b.human.identity.Identity.Id
		control, err = tcpconnect.NewControl(b.human.authenticated.Control, b.human.store, identity)
	}
	if err != nil {
		return nil, err
	}
	run, err := control.ResolvePrivateService(ctx, service.Id)
	if err != nil {
		if closer, ok := control.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	if run.Protocol != string(service.Protocol) || run.ManagedTLS == nil || *run.ManagedTLS != *endpoint {
		if closer, ok := control.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, connectionruntime.ErrUnavailable
	}
	if p.listener == nil {
		port := endpoint.Port
		// independently verified SDK identities cannot share a local capability
		// or compete for the same managed port. metadata retains the remote port.
		if b.parentPID > 0 {
			port = 0
		}
		base, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			if closer, ok := control.(io.Closer); ok {
				_ = closer.Close()
			}
			return nil, err
		}
		p.listener = connectionruntime.NewListenerSwitch(base)
		b.prepared[name] = p
	}
	b.mu.Lock()
	p.epoch++
	epoch := p.epoch
	p.err = nil
	b.mu.Unlock()
	p.ready = false
	if p.cancel != nil {
		p.cancel()
	}
	lifetime, cancel := context.WithCancel(b.lifetime)
	p.cancel = cancel
	prepared := false
	defer func() {
		if !prepared {
			cancel()
		}
	}()
	listener := p.listener.Next()
	ready := make(chan struct{})
	done := make(chan error, 1)
	connection.Port = listener.Addr().(*net.TCPAddr).Port
	configuration := tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: identity, Protocol: string(service.Protocol), TrustRevision: run.TrustRevision, ManagedTLS: endpoint, ServiceTLS: verification, Ready: func() error { close(ready); return nil }}
	b.workers.Go(func() {
		defer listener.Close()
		err := tcpconnect.Serve(lifetime, listener, configuration)
		b.mu.Lock()
		if p.epoch == epoch {
			if b.lifetime.Err() == nil {
				p.err = errors.Join(connectionruntime.ErrUnavailable, err)
			} else if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				b.cleanupErr = errors.Join(b.cleanupErr, err)
			}
		}
		b.mu.Unlock()
		done <- err
	})
	select {
	case <-ready:
	case err := <-done:
		return nil, errors.Join(connectionruntime.ErrUnavailable, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	connection.Kubeconfig, connection.Context = p.connection.Kubeconfig, p.connection.Context
	p.connection = connection
	p.control = control
	if b.workload != nil {
		session, err := b.workload.Session()
		if err != nil {
			return nil, err
		}
		p.sessionID = session.Id
	}
	if string(service.Protocol) == "http" || string(service.Protocol) == "kubernetes" {
		p.connection.URL = "https://" + net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port))
	}
	if string(service.Protocol) == "kubernetes" {
		if p.connection.Kubeconfig == "" {
			if err := b.prepareKube(ctx, name, p); err != nil {
				return nil, err
			}
		}
	}
	b.prepared[name] = p
	p.ready = true
	prepared = true
	return p, nil
}

// a lost exchange response must retry the same assertion and in-memory key.
// a replacement owner/key cannot take over an already committed execution.
func exchangeConnectionWorkload(ctx context.Context, client *workloadclient.Client, scope connectionruntime.Context, assertion string) (authorityv1.WorkloadSession, error) {
	var session authorityv1.WorkloadSession
	var err error
	for attempt := range 3 {
		session, err = client.Exchange(ctx, scope.TeamID, scope.ProjectKey, scope.SourceID, scope.Workload, assertion, scope.Services)
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
	b.prepareMu.Lock()
	defer b.prepareMu.Unlock()
	if _, err := b.healthy(); err != nil {
		return connectionruntime.Connection{}, err
	}
	service, found := b.services[name]
	if !found || validateProfileService(service) != nil || string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return connectionruntime.Connection{}, connectionruntime.ErrInvalid
	}
	p := b.prepared[name]
	if p != nil && time.Now().Before(p.authorizedUntil) {
		if snapshot, err := b.preparedLocked(name); err == nil {
			return snapshot, nil
		}
	}
	validUntil := time.Now().Add(30 * time.Second)
	if b.workload != nil {
		authorization, err := b.workload.CheckService(ctx, service.Id)
		if err != nil {
			return connectionruntime.Connection{}, err
		}
		if authorization.ValidUntil.Before(validUntil) {
			validUntil = authorization.ValidUntil
		}
	}
	b.mu.Lock()
	failed := p != nil && p.err != nil
	b.mu.Unlock()
	if p == nil || !p.ready || failed {
		var err error
		p, err = b.prepareService(ctx, name, p)
		if err != nil {
			return connectionruntime.Connection{}, err
		}
	}
	b.mu.Lock()
	err := p.err
	b.mu.Unlock()
	if err != nil {
		return connectionruntime.Connection{}, err
	}
	if b.human != nil && p.control != nil {
		if _, err := p.control.ResolvePrivateService(ctx, p.service.Id); err != nil {
			return connectionruntime.Connection{}, err
		}
	}
	p.authorizedUntil = validUntil
	return b.preparedLocked(name)
}

// Prepared is a local read only: no provider/control requests, key creation,
// listener setup or repair. an unprepared sibling must be explicitly awaited.
func (b *nativeConnectionBackend) Prepared(name string) (connectionruntime.Connection, error) {
	b.prepareMu.Lock()
	defer b.prepareMu.Unlock()
	return b.preparedLocked(name)
}

func (b *nativeConnectionBackend) preparedLocked(name string) (connectionruntime.Connection, error) {
	p := b.prepared[name]
	if p == nil || !p.ready {
		return connectionruntime.Connection{}, connectionruntime.ErrUnprepared
	}
	service, allowed := b.services[name]
	if !allowed || service.Id != p.service.Id || validateProfileService(service) != nil || string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return connectionruntime.Connection{}, connectionruntime.ErrUnprepared
	}
	b.mu.Lock()
	err := p.err
	deadline := b.deadline
	b.mu.Unlock()
	if err != nil {
		return connectionruntime.Connection{}, err
	}
	if !deadline.After(time.Now()) {
		return connectionruntime.Connection{}, connectionruntime.ErrExpired
	}
	if b.workload != nil {
		s, err := b.workload.Session()
		if err == nil && p.sessionID != s.Id {
			return connectionruntime.Connection{}, connectionruntime.ErrUnprepared
		}
		if err != nil || !s.LeaseExpiresAt.After(time.Now()) || !slices.Contains(s.ServiceIds, p.service.Id) {
			return connectionruntime.Connection{}, connectionruntime.ErrExpired
		}
	}
	result := p.connection
	result.ExpiresAt = deadline
	if p.service.Protocol != controlv1.Tcp {
		options := connectionruntime.TLSOptions{ServerName: p.service.ManagedTls.Hostname, RejectUnauthorized: true}
		result.SSL = &options
	}
	return result, nil
}
func (b *nativeConnectionBackend) healthy() (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.human != nil && b.workload == nil {
		b.deadline = time.Now().Add(time.Hour)
	}
	if !b.deadline.After(time.Now()) {
		return time.Time{}, connectionruntime.ErrExpired
	}
	return b.deadline, nil
}
func (b *nativeConnectionBackend) Renew(ctx context.Context) (time.Time, error) {
	if b.parentPID > 0 {
		process, err := os.FindProcess(b.parentPID)
		if err != nil || process.Signal(syscall.Signal(0)) != nil {
			return time.Time{}, connectionruntime.ErrExpired
		}
	}
	if _, err := b.healthy(); err != nil {
		return time.Time{}, err
	}
	b.mu.Lock()
	client := b.workload
	currentDeadline := b.deadline
	b.mu.Unlock()
	if client != nil {
		session, err := client.Renew(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if session.ExpiresAt.After(currentDeadline) || !session.LeaseExpiresAt.After(time.Now()) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
			return time.Time{}, connectionruntime.ErrExpired
		}
		b.mu.Lock()
		if b.workload == client && session.ExpiresAt.Before(b.deadline) {
			b.deadline = session.ExpiresAt
		}
		deadline := b.deadline
		b.mu.Unlock()
		return deadline, nil
	}
	b.mu.Lock()
	b.deadline = time.Now().Add(time.Hour)
	deadline := b.deadline
	b.mu.Unlock()
	return deadline, nil
}

// process lifetime belongs to the application; session deadlines remain in
// snapshots and data-plane admission, not in the local capability's lifetime.
func (b *nativeConnectionBackend) Persistent() bool { return b.scope.Workload == "" || b.parentPID > 0 }

func (b *nativeConnectionBackend) OwnerAlive() bool {
	if b.parentPID <= 0 {
		return true
	}
	p, err := os.FindProcess(b.parentPID)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

func (b *nativeConnectionBackend) Attach(ctx context.Context, assertion string) error {
	return b.attach(ctx, assertion, false)
}

func (b *nativeConnectionBackend) UseAssertion(ctx context.Context, assertion string) error {
	return b.attach(ctx, assertion, true)
}

func (b *nativeConnectionBackend) attach(ctx context.Context, assertion string, reuse bool) error {
	b.prepareMu.Lock()
	defer b.prepareMu.Unlock()
	if assertion == "" {
		var err error
		assertion, err = workloadclient.Acquire(ctx, b.acquisition, nil)
		if err != nil {
			return err
		}
	}
	if b.workload == nil {
		return connectionruntime.ErrInvalid
	}
	previous, err := b.workload.Session()
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(assertion))
	verified, known := b.assertions[hex.EncodeToString(digest[:])]
	if reuse && known && b.assertionChecks[verified.Digest].After(time.Now()) && verified.ExpiresAt.After(time.Now()) && b.verifiedSession == previous.Id && previous.LeaseExpiresAt.After(time.Now()) && previous.ExpiresAt.After(time.Now()) {
		b.verification = &verified
		return nil
	}
	session, err := b.workload.Attach(ctx, assertion)
	if err == nil {
		b.mu.Lock()
		b.deadline = session.ExpiresAt
		b.mu.Unlock()
		if session.AssertionExpiresAt != nil {
			b.rememberAssertion(assertion, *session.AssertionExpiresAt, session)
		} else {
			b.verification = nil
		}
		return nil
	}
	// a denied assertion does not stop other listeners. discard only their
	// cached admission observations so subsequent preparation checks live access.
	for _, p := range b.prepared {
		p.authorizedUntil = time.Time{}
	}
	if errors.Is(err, workloadclient.ErrSessionExpired) {
		// replacement authorizes future accepts from scratch. the old adapter and
		// its streams retain their old subject and never receive the new rights.
		if previous.Provider == controlv1.WorkloadGitHub {
			return connectionruntime.ErrExpired
		}
		next := b.replacement
		if next == nil {
			next, err = workloadclient.New(b.scope.Server, b.httpClient)
			if err != nil {
				return err
			}
			b.replacement = next
		}
		identity, err := next.IdentifyPolicy(ctx, b.scope.TeamID, b.scope.ProjectKey, b.scope.SourceID, b.scope.Workload, assertion)
		if err != nil {
			return err
		}
		if identity.Binding != previous.Binding {
			return connectionruntime.ErrUnauthorized
		}
		if b.replacementScope.Schema == 0 {
			b.replacementScope = b.scope
			b.replacementScope.Services = nil
			for _, name := range b.scope.Services {
				if slices.Contains(identity.Services, name) {
					b.replacementScope.Services = append(b.replacementScope.Services, name)
				}
			}
		}
		if len(b.replacementScope.Services) == 0 {
			return connectionruntime.ErrUnauthorized
		}
		session, err := exchangeConnectionWorkload(ctx, next, b.replacementScope, assertion)
		if err != nil {
			// only control-confirmed expiry permits a new retry nonce/key after
			// an exchange response was lost for longer than its original lease.
			if errors.Is(err, workloadclient.ErrSessionExpired) {
				b.replacement = nil
				b.replacementScope = connectionruntime.Context{}
			}
			return err
		}
		if session.Binding != previous.Binding {
			_ = next.Revoke(ctx)
			return connectionruntime.ErrUnauthorized
		}
		inventory, err := next.ListServices(ctx)
		if err != nil {
			return err
		}
		services := map[string]controlv1.PrivateService{}
		metadata := projectmeta.Metadata{Version: projectmeta.Version, Services: map[string]projectmeta.Service{}}
		for _, s := range inventory.Services {
			if !slices.Contains(b.scope.Services, s.Service) || string(s.Protocol) != config.Protocol(b.project.Config.Services[s.Service]) {
				continue
			}
			value, err := projectmeta.NewEndpoint(s.ManagedTls.Hostname, s.ManagedTls.Hostname, string(s.Protocol), s.ManagedTls.Port, s.ManagedTls.Public)
			if err != nil {
				continue
			}
			services[s.Service] = controlv1.PrivateService{Id: s.Id, Name: s.Service, TeamId: session.TeamId, Protocol: s.Protocol, Enabled: true, ManagedTls: &s.ManagedTls, KubernetesAuth: s.KubernetesAuth}
			metadata.Services[s.Service] = value
			if metadata.Namespace == "" {
				metadata.Namespace = value.Namespace
			}
		}
		if err := metadata.Validate(); err != nil {
			return err
		}
		b.mu.Lock()
		b.workload = next
		b.deadline = session.ExpiresAt
		b.mu.Unlock()
		b.services, b.metadata = services, metadata.Public(false)
		b.rememberAssertion(assertion, identity.AssertionExpiresAt, session)
		b.replacement = nil
		b.replacementScope = connectionruntime.Context{}
		for name, p := range b.prepared {
			if _, found := services[name]; !found {
				continue
			}
			if _, err := b.prepareService(ctx, name, p); err != nil {
				b.mu.Lock()
				p.err = err
				b.mu.Unlock()
			}
		}
		return nil
	}
	return err
}

func (b *nativeConnectionBackend) rememberAssertion(assertion string, expires time.Time, session authorityv1.WorkloadSession) {
	if assertion == "" || !expires.After(time.Now()) {
		b.verification = nil
		return
	}
	digest := sha256.Sum256([]byte(assertion))
	b.verification = &connectionruntime.AssertionVerification{Digest: hex.EncodeToString(digest[:]), Binding: session.Binding, ExpiresAt: expires}
	if b.assertions == nil || b.verifiedSession != session.Id {
		b.assertions = map[string]connectionruntime.AssertionVerification{}
		b.assertionChecks = map[string]time.Time{}
	}
	for key, proof := range b.assertions {
		if !proof.ExpiresAt.After(time.Now()) {
			delete(b.assertions, key)
			delete(b.assertionChecks, key)
		}
	}
	if len(b.assertions) >= 128 {
		for key := range b.assertions {
			delete(b.assertions, key)
			delete(b.assertionChecks, key)
			break
		}
	}
	b.assertions[b.verification.Digest] = *b.verification
	checkedUntil := time.Now().Add(30 * time.Second)
	if expires.Before(checkedUntil) {
		checkedUntil = expires
	}
	b.assertionChecks[b.verification.Digest] = checkedUntil
	b.verifiedSession = session.Id
}
func (b *nativeConnectionBackend) Verification() *connectionruntime.AssertionVerification {
	b.prepareMu.Lock()
	defer b.prepareMu.Unlock()
	if b.verification == nil || !b.verification.ExpiresAt.After(time.Now()) {
		return nil
	}
	v := *b.verification
	return &v
}

func (b *nativeConnectionBackend) PublicRuntime() projectmeta.PublicMetadata {
	b.prepareMu.Lock()
	defer b.prepareMu.Unlock()
	return b.metadata
}
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
	for _, p := range b.prepared {
		if p.listener != nil {
			result = errors.Join(result, p.listener.Close())
		}
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
	if b.scope.Workload != "" {
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
		if b.scope.Workload != "" {
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
