package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
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
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (a *appRuntime) publishApplication(ctx context.Context, request publisherprotocol.ApplicationPublication) (_ publisherprotocol.AcceptedPublication, result error) {
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
	publicRequest := request
	publicRequest.Auth = nil
	encoded, err := json.Marshal(publicRequest)
	if err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	fingerprint := sha256.Sum256(encoded)
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
		accepted := *previous.application
		accepted.Reused = true
		return accepted, nil
	}
	if a.ApplicationAuthority == nil {
		return publisherprotocol.AcceptedPublication{}, publisherprotocol.ErrApplicationUnavailable
	}
	selection := invocation.ApplicationSelection{ServerURL: request.ServerUrl, InvocationID: request.InvocationId, Target: request.Target, ResourceID: valueOrEmpty(request.ResourceId), Auth: slices.Clone(request.Auth), RequirePostQuantum: request.RequirePostQuantum, IP: request.Ip, Limits: request.Limits}
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
	cleanup := applicationCleanup(resourceCleanup)
	transferred, cleanupOwned, id := false, false, ""
	defer func() {
		if !transferred {
			if id != "" {
				result = errors.Join(result, a.manager.Unregister(id, request.Owner))
				a.mu.Lock()
				delete(a.prepared, id)
				a.mu.Unlock()
			}
			if !cleanupOwned {
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
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	// SetCleanup gave the registration ownership before the worker starts. do not
	// also give it to Workers.Run: a failed attempt is retryable, not a permanent
	// publication error after a later attempt succeeds.
	configuration := publisherapp.Configuration{Publisher: cfg, Inspection: policy, SkipAutomaticReadiness: true}
	if a.AttachPublication != nil {
		if err := a.AttachPublication(ctx, publisherapp.Service{Name: request.InvocationId, RegistrationID: id, Target: request.Target}, &configuration.Publisher); err != nil {
			return publisherprotocol.AcceptedPublication{}, err
		}
	}
	var accepted publisherprotocol.AcceptedPublication
	accepted.Registration = publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}
	accepted.PublicUrlId, accepted.Hostname, accepted.PublicUrl = publicURL.Id, publicURL.CanonicalHostname, address
	a.mu.Lock()
	a.prepared[id] = appPreparation{configuration: configuration, applicationFingerprint: fingerprint, application: &accepted, refreshApplicationAuth: grant.RefreshAuth}
	a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	if err := ctx.Err(); err != nil {
		return publisherprotocol.AcceptedPublication{}, err
	}
	transferred = true
	return accepted, nil
}

func applicationAuthorityError(err error) error {
	if errors.Is(err, publisherprotocol.ErrApplicationAuthInvalid) || errors.Is(err, publisherprotocol.ErrApplicationDenied) || errors.Is(err, publisherprotocol.ErrApplicationUnavailable) {
		return err
	}
	reason, _ := failure.ReasonOf(err)
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrNotFound) || reason == failure.Authentication || reason == failure.ServerDenied || reason == failure.PublisherGrantMismatch {
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
		if err := cleanup(ctx); err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
			return err
		}
		done = true
		return nil
	}
}
