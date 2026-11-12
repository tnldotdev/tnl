package local

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *appRuntime) publishApplication(ctx context.Context, request publisherprotocol.ApplicationPublication) (_ publisherprotocol.AcceptedPublication, result error) {
	defer func() {
		result = errors.Join(result, context.Cause(ctx))
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.shuttingDown && result != nil && !failure.Only(result, context.Canceled) {
			a.shutdownPreparationErr = errors.Join(a.shutdownPreparationErr, result)
		}
	}()
	if err := validateApplication(request); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	// renewal/recovery keeps only a digest of public request facts, never auth.
	fingerprint, err := applicationRequestFingerprint(request)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if a.ApplicationAuthority == nil {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationUnavailable
	}
	if _, err := applicationSourceProof(request.Auth, true); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	publication, err := a.applicationCheckpoint(ctx, request, fingerprint)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := a.consumeApplicationChallenge(ctx, request, publication); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name != request.InvocationId || service.RegistrationID == "" {
			continue
		}
		a.mu.Lock()
		previous := a.prepared[service.RegistrationID]
		a.mu.Unlock()
		if previous.application == nil || previous.refreshApplicationAuth == nil || previous.applicationFingerprint != fingerprint {
			return publisherprotocol.AcceptedPublication{}, publisherapp.ErrOwnerConflict
		}
		if !a.manager.CurrentRegistration(request.InvocationId, service.RegistrationID, request.Target) {
			return publisherprotocol.AcceptedPublication{}, publisherapp.ErrRegistrationStale
		}
		proof := slices.Clone(request.Auth)
		refreshErr := previous.refreshApplicationAuth(ctx, proof)
		clear(proof)
		if refreshErr != nil {
			a.manager.RecordWarning(request.InvocationId, service.RegistrationID, "runtime.credential_refresh_failed")
			return publisherprotocol.AcceptedPublication{}, applicationAuthorityError(refreshErr)
		}
		if err := a.manager.RenewTarget(service.RegistrationID, request.Owner, request.Target); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		// register is idempotent for a running worker and restarts one stopped at
		// its old confirmed fence after an uncertain refresh has been resolved.
		if err := a.manager.RegisterContext(ctx, service.RegistrationID, request.Owner, request.Target, ""); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
		accepted := *previous.application
		accepted.Reused = true
		return accepted, nil
	}
	if a.ApplicationAuthority == nil {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationUnavailable
	}
	selection := invocation.ApplicationSelection{ServerURL: request.ServerUrl, InvocationID: request.InvocationId, Target: request.Target, ResourceID: valueOrEmpty(request.ResourceId), Auth: slices.Clone(request.Auth), RequirePostQuantum: request.RequirePostQuantum, IP: request.Ip, Limits: request.Limits}
	selection.Publication = publication
	prior, err := publication.Snapshot(ctx)
	if err != nil {
		clear(selection.Auth)
		return publisherprotocol.AcceptedPublication{}, err
	}
	recovered := prior.PublicURL != nil
	clear(prior.NativeKey)
	if request.Allocate != nil {
		selection.Namespace = request.Allocate.Namespace
	}
	if request.AccessMode != nil {
		mode := controlv1.VisitorAccessMode(*request.AccessMode)
		selection.AccessMode = &mode
	}
	grant, resolveErr := a.ApplicationAuthority.ResolveApplicationPublication(ctx, selection)
	clear(selection.Auth)
	resourceCleanup := grant.Cleanup
	if request.ResourceId != nil {
		resourceCleanup = nil
	}
	retire := applicationCleanup(func(ctx context.Context) error {
		ctx, cancel := a.applicationCleanupContext(ctx)
		defer cancel()
		var resourceErr, releaseErr error
		if resourceCleanup != nil {
			resourceErr = resourceCleanup(ctx)
			if applicationResourceGone(resourceErr) {
				resourceErr = nil
			}
		}
		if grant.Release != nil {
			releaseErr = grant.Release(ctx)
		}
		if err := errors.Join(resourceErr, releaseErr); err != nil {
			return err
		}
		record, err := publication.Snapshot(ctx)
		if err != nil {
			return err
		}
		defer clear(record.NativeKey)
		if record.Phase == clientstate.ApplicationCleanupDone {
			return nil
		}
		record.Phase, record.NativeKey = clientstate.ApplicationCleanupDone, nil
		return publication.Checkpoint(ctx, record)
	})
	var retainRecovery atomic.Bool
	cleanup := func() error {
		checkpoint, cancel := a.applicationCleanupContext(context.Background())
		defer cancel()
		record, err := publication.Snapshot(checkpoint)
		if err != nil {
			return err
		}
		clear(record.NativeKey)
		if record.Phase != clientstate.ApplicationCleanupPending && record.Phase != clientstate.ApplicationDenied && (record.Phase == clientstate.ApplicationRefreshPending || retainRecovery.Load()) && time.Now().Before(record.OwnerExpiresAt) && (a.manager.Alive == nil || a.manager.Alive(record.Binding.PID)) {
			return nil
		}
		if err := publication.RequestCleanup(checkpoint); err != nil {
			return err
		}
		return retire()
	}
	transferred, cleanupOwned, id := false, false, ""
	defer func() {
		if !transferred {
			// a live owner may resolve an uncertain remote reply using this same
			// key/nonce. cancellation is an abort, not a request for recovery.
			if id == "" && ctx.Err() == nil && errors.Is(resolveErr, publisheridentity.ErrApplicationSessionUncertain) {
				return
			}
			checkpoint, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			var intentErr error
			if recovered && ctx.Err() != nil {
				retainRecovery.Store(true)
			} else {
				intentErr = publication.RequestCleanup(checkpoint)
			}
			cancel()
			result = errors.Join(result, intentErr)
			if id != "" {
				result = errors.Join(result, a.manager.Unregister(id, request.Owner))
				a.mu.Lock()
				delete(a.prepared, id)
				a.mu.Unlock()
			}
			if !cleanupOwned && intentErr == nil {
				result = errors.Join(result, cleanup())
			}
		}
	}()
	if resolveErr != nil {
		return publisherprotocol.AcceptedPublication{}, applicationAuthorityError(resolveErr)
	}
	publicURL := grant.PublicURL
	hostname, hostnameErr := naming.CanonicalizeHostname(publicURL.CanonicalHostname)
	allocatedHostname := false
	if request.Allocate != nil {
		label, found := strings.CutSuffix(publicURL.CanonicalHostname, "."+request.Allocate.Namespace)
		allocatedHostname = found && naming.ValidRandomHostnameLabel(label)
	}
	if grant.Control == nil || grant.RefreshAuth == nil || !opaqueid.Valid(grant.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		hostnameErr != nil || hostname != publicURL.CanonicalHostname ||
		!opaqueid.Valid(publicURL.Id, opaqueid.PublicURLPrefix) || publicURL.ServiceProtocol != controlv1.Http || publicURL.Purpose != controlv1.App || publicURL.LifecycleState != controlv1.Enabled || publicURL.PublisherPool != nil && *publicURL.PublisherPool ||
		request.ResourceId != nil && (publicURL.Id != *request.ResourceId || publicURL.Ephemeral || request.AccessMode != nil || request.Ip != nil || request.Limits != nil) ||
		request.Allocate != nil && (!publicURL.Ephemeral || grant.Cleanup == nil || publicURL.Target != request.Target || !allocatedHostname) {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationDenied
	}
	if request.RequirePostQuantum != nil && publicURL.RequirePostQuantum != *request.RequirePostQuantum || request.AccessMode != nil && publicURL.AccessMode != controlv1.VisitorAccessMode(*request.AccessMode) {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationDenied
	}
	if request.Allocate != nil && request.AccessMode == nil && publicURL.AccessMode != controlv1.Restricted {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationDenied
	}
	profile, err := a.state.Server(ctx, request.ServerUrl)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	limits, err := invocationLimits(request.Limits)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := a.manager.AddService(publisherapp.Service{Name: request.InvocationId, Directory: ".", ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/"}}); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	address := "https://" + publicURL.CanonicalHostname
	id, err = a.manager.Reserve(request.InvocationId, request.Owner, request.Pid, address)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := a.manager.SetCleanup(id, request.Owner, cleanup); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	cleanupOwned = true
	policy, err := config.ResolveInspection(nil, "http")
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := publisher.Config{Control: grant.Control, Identity: grant.Control, Audit: grant.Control, VisitorControl: grant.Control, BrowserControl: grant.Control, Shares: grant.Control, PublisherIdentityID: grant.PublisherIdentityID, ControlURL: request.ServerUrl, State: profile, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, PolicyRevision: uint64(publicURL.PolicyRevision), Hostname: publicURL.CanonicalHostname, ProjectRoot: a.project.Root, Target: request.Target, ServiceProtocol: "http", Limits: limits, Ephemeral: publicURL.Ephemeral, AssignedPublicURL: &publicURL, AccessMode: publicURL.AccessMode, RequirePostQuantum: &publicURL.RequirePostQuantum, PreserveSavedPublicURLTarget: true, QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: tlsConfig}}
	// reserve part of the native owner's bounded shutdown window for original-key
	// cleanup after all sibling visitor drains have finished.
	cfg.DrainTime = 5 * time.Second
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	if grant.CheckServing != nil {
		cfg.AdmitRequest = func(*http.Request, publisher.PublishRunIdentity) error { return grant.CheckServing() }
		cfg.AdmitVisitor = func(context.Context, publisher.Visitor) error { return grant.CheckServing() }
	}
	// SetCleanup gave the registration ownership before the worker starts. do not
	// also give it to Workers.Run: a failed attempt is retryable, not a permanent
	// publication error after a later attempt succeeds.
	configuration := publisherapp.Configuration{Publisher: cfg, Inspection: policy, SkipAutomaticReadiness: true, Authority: grant.Run}
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, publisherapp.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}, &configuration.Publisher); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
	}
	var accepted publisherprotocol.AcceptedPublication
	accepted.Registration = publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}
	accepted.PublicUrlId, accepted.Hostname, accepted.PublicUrl = publicURL.Id, publicURL.CanonicalHostname, address
	accepted.Reused = recovered
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, applicationFingerprint: fingerprint, application: &accepted, refreshApplicationAuth: grant.RefreshAuth}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := ctx.Err(); err != nil && !recovered {
		return publisherprotocol.AcceptedPublication{}, err
	}
	transferred = true
	return accepted, nil
}

func applicationAuthorityError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, publisherprotocol.ErrApplicationAuthInvalid) || errors.Is(err, publisherprotocol.ErrApplicationDenied) || errors.Is(err, publisherprotocol.ErrApplicationUnavailable) {
		return err
	}
	reason, _ := failure.ReasonOf(err)
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, publisheridentity.ErrScope) || reason == failure.Authentication || reason == failure.ServerResourceNotFound || reason == failure.ServerDenied || reason == failure.PublisherGrantMismatch {
		return errors.Join(publisherprotocol.ErrApplicationDenied, err)
	}
	if reason == failure.ServerResponseInvalid {
		return errors.Join(publisherprotocol.ErrApplicationAuthInvalid, err)
	}
	return errors.Join(publisherprotocol.ErrApplicationUnavailable, err)
}

func validateApplication(request publisherprotocol.ApplicationPublication) error {
	canonical, err := targetsyntax.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target || len(request.Target) > 4096 || request.Version != 1 || !publisherprotocol.ValidOwner(request.Owner) || request.Pid <= 0 || !opaqueid.Valid(request.InvocationId, opaqueid.InvocationPrefix) || (request.ResourceId == nil) == (request.Allocate == nil) {
		return errors.New("invalid application publication")
	}
	server, err := clientstate.CanonicalServer(request.ServerUrl)
	if err != nil || server != request.ServerUrl {
		return errors.New("application publication requires an explicit canonical control URL")
	}
	var auth map[string]json.RawMessage
	if json.Unmarshal(request.Auth, &auth) != nil || len(auth) == 0 || bytes.Equal(bytes.TrimSpace(request.Auth), []byte("null")) {
		return publisherprotocol.ErrApplicationAuthInvalid
	}
	if request.ResourceId != nil && !opaqueid.Valid(*request.ResourceId, opaqueid.PublicURLPrefix) {
		return publisherprotocol.ErrApplicationDenied
	}
	if request.Allocate != nil {
		namespace, err := naming.CanonicalizeHostname(request.Allocate.Namespace)
		if err != nil || namespace != request.Allocate.Namespace {
			return publisherprotocol.ErrApplicationDenied
		}
	}
	if request.AccessMode != nil && !request.AccessMode.Valid() || request.Ip != nil && len(*request.Ip) > 32 {
		return errors.New("invalid application publication policy")
	}
	_, err = invocationLimits(request.Limits)
	return err
}

// serialize worker/close cleanup and remember success, not a failed attempt.
// a failed close retains its registration so the same handle can retry cleanup.
func applicationCleanup(cleanup func(context.Context) error) func() error {
	var mu sync.Mutex
	done := cleanup == nil
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := cleanup(ctx); err != nil && !applicationResourceGone(err) {
			return err
		}
		done = true
		return nil
	}
}

// a missing resource is successful cleanup only when every cause is that exact
// control result. the typed sentinel itself wraps a leaf, so do not strip it
// before comparison or let errors.Is hide a separate joined failure.
func applicationResourceGone(err error) bool {
	if err == clientcontrol.ErrNotFound {
		return true
	}
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if len(joined.Unwrap()) == 0 {
			return false
		}
		for _, cause := range joined.Unwrap() {
			if !applicationResourceGone(cause) {
				return false
			}
		}
		return true
	}
	return applicationResourceGone(errors.Unwrap(err))
}
