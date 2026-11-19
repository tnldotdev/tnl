package local

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisheradhoc "github.com/tnldotdev/tnl/internal/publisher/adhoc"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *appRuntime) invocation(ctx context.Context, request publisherprotocol.Invocation) (_ publisherprotocol.Registration, result error) {
	// keep the original private request independent of caller-owned pointers.
	encoded, err := json.Marshal(request)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	var original publisherprotocol.Invocation
	if err := json.Unmarshal(encoded, &original); err != nil {
		return publisherprotocol.Registration{}, err
	}
	request = original
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	canonical, err := targetsyntax.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target || request.PublisherCredentialFile != "" && request.PublisherIdentityId != "" ||
		request.AccessMode != nil && !request.AccessMode.Valid() || request.Ip != nil && len(*request.Ip) > 32 {
		return publisherprotocol.Registration{}, errors.New("invalid invocation target or policy")
	}
	options, err := invocationOptions(request)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	var supplied *invocationCertificate
	if request.Certificate != nil {
		supplied = &invocationCertificate{}
		if err := supplied.replace(request.Certificate.CertificatePem, request.Certificate.PrivateKeyPem); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	file := request.PublisherCredentialFile
	if file == "" && request.PublisherIdentityId == "" && request.Deployment == nil && a.sdkPublisher == nil {
		file = os.Getenv("TNL_PUBLISHER_CREDENTIAL_FILE")
	}
	if file != "" && (!filepath.IsAbs(file) || len(file) > 4096 || strings.ContainsRune(file, 0)) {
		return publisherprotocol.Registration{}, credentialfile.ErrInvalid
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name != request.InvocationId || service.RegistrationID == "" {
			continue
		}
		a.mu.Lock()
		previous := a.prepared[service.RegistrationID].invocation
		a.mu.Unlock()
		first, _ := json.Marshal(previous)
		next, _ := json.Marshal(request)
		if previous == nil || string(first) != string(next) {
			return publisherprotocol.Registration{}, publisherapp.ErrOwnerConflict
		}
		if err := a.manager.Renew(service.RegistrationID, request.Owner); err != nil {
			return publisherprotocol.Registration{}, err
		}
		return publisherprotocol.Registration{Version: 1, RegistrationID: service.RegistrationID, Owner: request.Owner, Target: request.Target}, nil
	}
	var native *publisheridentity.Native
	var saved controlv1.Service
	var cfg publisherservice.RunConfig
	var credentialExpiry time.Time
	// cleanup is installed before allocation: an uncertain response still owns
	// recovery of the exact invocation, even if cancellation wins registration.
	var cleanup func(context.Context) error
	transferred, id := false, ""
	ownDeadline := sync.OnceValue(func() time.Time { return time.Now().Add(10 * time.Second) })
	deadline := func() time.Time {
		if id != "" {
			return a.manager.PublicationShutdownDeadline(id)
		}
		return ownDeadline()
	}
	options.ShutdownDeadline = deadline
	defer func() {
		if !transferred {
			if id != "" {
				err := a.manager.Unregister(id, request.Owner)
				result = errors.Join(result, err)
				if err == nil {
					a.mu.Lock()
					delete(a.prepared, id)
					a.mu.Unlock()
				}
			}
			if cleanup != nil {
				finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline())
				defer cancel()
				result = errors.Join(result, cleanup(finish))
			}
		}
	}()
	server := ""
	if a.sdkPublisher != nil || request.EnrolledService != "" {
		var selection deploymentInvocation
		selection, err = a.prepareEnrolledInvocation(ctx, request)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		native, saved, cfg = selection.native, selection.service, selection.config
		server = native.ControlURL()
	} else if request.Deployment != nil {
		var selection deploymentInvocation
		selection, err = a.prepareDeploymentInvocation(ctx, request, options)
		cleanup = selection.cleanup
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		native, saved = selection.native, selection.service
		credentialExpiry = selection.expiresAt
		server = native.ControlURL()
		cfg = selection.config
	} else {
		server = valueOrEmpty(a.project.Config.Server)
		if request.ServerUrl != nil {
			selected, err := clientstate.CanonicalServer(*request.ServerUrl)
			if err != nil {
				return publisherprotocol.Registration{}, err
			}
			if server != "" && server != selected {
				return publisherprotocol.Registration{}, publisheridentity.ErrScope
			}
			server = selected
		}
		server, err = clientserver.Select(ctx, a.state, server)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		profile, err := a.state.Server(ctx, server)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		control, err := clientcontrol.New(server, nil, "")
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		authority, err := clientauthority.New(server, nil, "")
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		native, err = publisheridentity.ResolveAdHoc(ctx, profile, publisheridentity.NativeControl{Services: control, Allocations: control}, authority, server, "", "", "", file, "", request.PublisherIdentityId, nil)
		if err != nil {
			if file != "" && errors.Is(err, publisheridentity.ErrScope) {
				return publisherprotocol.Registration{}, credentialfile.ErrInvalid
			}
			return publisherprotocol.Registration{}, err
		}
		options.ControlURL, options.State, options.Publisher = server, profile, native
		prepared, err := publisheradhoc.Prepare(ctx, options)
		if prepared != nil {
			cleanup = invocationCleanup(prepared.Cleanup, time.Time{}, deadline)
		}
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		saved, cfg = prepared.Service, prepared.Config
	}
	if err := a.manager.AddService(publisherapp.Service{Name: request.InvocationId, Directory: ".", ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/"}}); err != nil {
		return publisherprotocol.Registration{}, err
	}
	address := ""
	var privateTarget targettransport.Transport
	if saved.Endpoint.Public {
		address = "https://" + saved.Endpoint.Hostname
	} else {
		trust, err := publisheridentity.ServiceTrust(saved)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
		privateTarget, err = targettransport.FromTrust(config.ProtocolHTTP, trust)
		if err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	id, err = a.manager.Reserve(request.InvocationId, request.Owner, request.Pid, address)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: publisherapp.Configuration{Cleanup: cleanup}, invocation: &request}
	a.mu.Unlock()
	policy, err := config.ResolveInspection(nil, "http")
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	service := publisherapp.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}
	cfg.ShutdownDeadline = deadline
	cfg.CertificateExport = new(publisherservice.CertificateExport)
	if supplied != nil {
		cfg.SuppliedCertificate = supplied.current
	}
	cfg.ShutdownContext = a.manager.PublicationShutdownContext(id)
	cfg.TransportTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.InspectionMode = policy.Mode
	if !request.TelemetryDisabled {
		cfg.Telemetry = a.Telemetry
	}
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, service, &cfg); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	expires := credentialExpiry
	if saved.ExpiresAt != nil && (expires.IsZero() || saved.ExpiresAt.Before(expires)) {
		expires = *saved.ExpiresAt
	}
	publication := a.invocationPublication(service, cfg, address, expires)
	if address == "" {
		publication.Check = func(ctx context.Context, service publisherapp.Service) publisherapp.Observation {
			return publisherapp.ProbeServiceTarget(ctx, service, privateTarget)
		}
	}
	publication.Options = clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Project: a.project.Root,
		Target: request.Target, ServiceID: saved.Id, ServiceProtocol: saved.Protocol}
	configuration := publisherapp.Configuration{Service: publication, Inspection: policy, Cleanup: cleanup}
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, invocation: &request, telemetryDisabled: request.TelemetryDisabled, certificate: supplied, certificateExport: cfg.CertificateExport}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
		return publisherprotocol.Registration{}, err
	}
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	transferred = true
	return publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, nil
}

// both allocation authorities receive the same app-selected options. adhoc owns
// request construction, target trust, saved-fact validation, and native cleanup.
func invocationOptions(request publisherprotocol.Invocation) (publisheradhoc.Options, error) {
	limits, err := requestlimit.ParseLimits(request.Limits)
	if err != nil {
		return publisheradhoc.Options{}, err
	}
	options := publisheradhoc.Options{InvocationID: request.InvocationId, Target: request.Target, Limits: limits, Public: request.Public}
	if request.RequirePostQuantum != nil {
		options.RequirePostQuantum = *request.RequirePostQuantum
	}
	if request.AccessMode != nil {
		options.AccessMode = controlv1.VisitorAccessMode(*request.AccessMode)
	}
	if request.Ip != nil {
		options.IP = *request.Ip
	}
	return options, nil
}

// the app worker owns journaling and joined cleanup. these callbacks bind its
// observations and public readiness proof to the actual prepared service run.
func (a *appRuntime) invocationPublication(service publisherapp.Service, base publisherservice.RunConfig, address string, expires time.Time) *publisherapp.ServicePublication {
	var mu sync.Mutex
	var current httpaccess.ReadinessRun
	var proof *httpaccess.ReadinessProof
	publication := &publisherapp.ServicePublication{URL: address}
	publication.Check = func(ctx context.Context, service publisherapp.Service) publisherapp.Observation {
		mu.Lock()
		run, captured := current, proof
		mu.Unlock()
		failed := publisherapp.Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber,
			Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.target_changed"}
		if run.Number != service.RunNumber || captured == nil {
			return failed
		}
		secret, err := captured.Renew()
		if err != nil {
			return failed
		}
		service.PublicURL = address
		observation := publisherapp.ProbeWithProof(ctx, service, nil, secret)
		mu.Lock()
		unchanged := current == run && proof == captured
		mu.Unlock()
		if !unchanged || captured.HeaderValue() != "" {
			return failed
		}
		return observation
	}
	publication.Run = func(ctx context.Context, tunnel *clientstate.Tunnel, observe func(uint64, bool) error, summary inspection.Observer) error {
		if !expires.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, expires)
			defer cancel()
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		cfg := base
		cfg.ShutdownContext = a.manager.PublicationShutdownContext(service.RegistrationID)
		cfg.ObserveSummary = func(value inspection.Summary) {
			if summary != nil {
				summary(value)
			}
			if base.ObserveSummary != nil {
				base.ObserveSummary(value)
			}
		}
		prepared, ready, admit, status := cfg.Prepared, cfg.Ready, cfg.AdmitRequest, cfg.ObserveReadiness
		var notified bool
		var observationErr error
		cfg.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
			mu.Lock()
			current = httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: preparation.ServiceId},
				ID: preparation.ServiceRunId, Number: uint64(preparation.RunNumber), Hostname: preparation.Hostname}
			proof = nil
			mu.Unlock()
			notified = false
			if err := observe(uint64(preparation.RunNumber), false); err != nil {
				return err
			}
			hostname := ""
			if preparation.RunHostname != nil {
				hostname = *preparation.RunHostname
			}
			if err := tunnel.SetServiceRun(ctx, preparation.ServiceRunId, uint64(preparation.RunNumber), hostname); err != nil {
				return err
			}
			if prepared != nil {
				return prepared(preparation)
			}
			return nil
		}
		cfg.ReadinessProof = nil
		if address != "" {
			cfg.ReadinessProof = func(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
				mu.Lock()
				defer mu.Unlock()
				if run != current {
					return nil
				}
				if base.ReadinessProof != nil {
					proof = base.ReadinessProof(run)
				} else {
					proof, _ = httpaccess.NewReadinessProof(run, "/")
				}
				return proof
			}
		}
		cfg.AdmitRequest = func(r *http.Request) error {
			mu.Lock()
			run := current
			mu.Unlock()
			if ctx.Err() != nil || !a.manager.CurrentRun(service.Name, service.RegistrationID, service.Target, run.Number) {
				return publisherapp.ErrRegistrationStale
			}
			if admit != nil {
				return admit(r)
			}
			return nil
		}
		cfg.Ready = func() error {
			mu.Lock()
			run := current
			mu.Unlock()
			if err := observe(run.Number, true); err != nil {
				return err
			}
			notified = true
			if ready != nil {
				return ready()
			}
			return nil
		}
		cfg.ObserveReadiness = func(state publisherservice.RunStatus) {
			if status != nil {
				status(state)
			}
			if !notified || ctx.Err() != nil || observationErr != nil {
				return
			}
			mu.Lock()
			run := current
			mu.Unlock()
			active, ok := a.manager.ServiceForRun(service.Name, service.RegistrationID, service.Target, run.Number)
			if ok && active.Routable == state.Ready {
				return
			}
			if err := observe(run.Number, state.Ready); err != nil {
				observationErr = err
				cancel()
			}
		}
		return errors.Join(publisherservice.Publish(ctx, cfg), observationErr)
	}
	return publication
}

// retain one exact allocation for transient retries. permanent authority loss or
// the captured grant deadline retires only local ownership, never remote state.
func invocationCleanup(remove func(context.Context) error, expiresAt time.Time, deadline func() time.Time) func(context.Context) error {
	if deadline == nil {
		deadline = sync.OnceValue(func() time.Time { return time.Now().Add(10 * time.Second) })
	}
	var mu sync.Mutex
	cleaned := false
	var permanent error
	return func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if cleaned || remove == nil {
			return nil
		}
		if permanent != nil {
			return permanent
		}
		if !expiresAt.IsZero() && !time.Now().Before(expiresAt) {
			permanent = errors.Join(publisherapp.ErrCleanupPermanent, auth.ErrDeploymentCredential)
			return permanent
		}
		// the manager supplies the current operation's bound, including a later
		// explicit retry. only unbounded callers need the original fallback.
		if _, bounded := ctx.Deadline(); !bounded {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline())
			defer cancel()
		}
		err := remove(ctx)
		if err == nil || failure.Only(err, clientcontrol.ErrNotFound) {
			cleaned = true
			return nil
		}
		reason, _ := failure.ReasonOf(err)
		if errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrUnauthenticated) ||
			errors.Is(err, publisheridentity.ErrScope) || reason == failure.ServerDenied {
			permanent = errors.Join(publisherapp.ErrCleanupPermanent, err)
			return permanent
		}
		return err
	}
}
