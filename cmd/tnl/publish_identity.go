package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// issuedNativePublisher reuses one locally owned key for the selected namespace.
// the control session only issues enrollment; run creation uses signed identity.
func issuedNativePublisher(ctx context.Context, services publisherServices) (*nativeauth.Native, error) {
	digest := sha256.Sum256([]byte(services.teamID + "\x00" + services.domainID))
	scope := "owner-namespace:" + hex.EncodeToString(digest[:])
	lock, err := services.state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	control, authority := services.authenticated.Control, services.authenticated.Authority
	saved, found, err := services.state.SelectedPublisherIdentity(ctx, "namespace", scope)
	if err != nil {
		return nil, err
	}
	if found {
		var identity authorityv1.PublisherEnrollmentResult
		if err := json.Unmarshal(saved.PublicDocument, &identity); err != nil || identity.ClientId != saved.ID {
			return nil, nativeauth.ErrScope
		}
		if identity.ClientId != "" {
			if identity.Kind != authorityv1.Namespace || identity.TeamId != services.teamID || identity.DomainId == nil || *identity.DomainId != services.domainID || identity.Namespace == nil || *identity.Namespace != services.namespace {
				return nil, nativeauth.ErrScope
			}
			native, _, err := nativeauth.LoadNative(ctx, services.state, control, authority, identity.ClientId)
			return native, err
		}
	}
	pending, found, err := services.state.PendingPublisherEnrollmentForSelection(ctx, "namespace", scope)
	if err != nil {
		return nil, err
	}
	if !found {
		body := controlv1.CreatePublisherEnrollmentRequest{TeamId: services.teamID, DomainId: &services.domainID, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "tnl"}
		enrollment, err := control.CreatePublisherEnrollment(ctx, body)
		if err != nil {
			return nil, err
		}
		if enrollment.Kind != controlv1.PublisherEnrollmentKindNamespace || enrollment.TeamId != services.teamID || enrollment.DomainId == nil || *enrollment.DomainId != services.domainID || enrollment.Namespace == nil || *enrollment.Namespace != services.namespace || enrollment.EnrollmentKey == "" {
			return nil, failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, nativeauth.ErrScope)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pending = clientstate.PendingPublisherEnrollment{EnrollmentID: enrollment.Id, SelectionKind: "namespace", SelectionKey: scope, PublicKey: public, SigningKey: private, EnrollmentSecret: []byte(enrollment.EnrollmentKey), ExpiresAt: time.Now().Add(10 * time.Minute)}
		if err := services.state.SavePendingPublisherEnrollment(ctx, pending); err != nil {
			return nil, err
		}
	}
	native, identity, err := nativeauth.EnrollNative(ctx, services.state, control, authority, string(pending.EnrollmentSecret))
	if err != nil {
		return nil, err
	}
	if identity.Kind != authorityv1.Namespace || identity.TeamId != services.teamID || identity.DomainId == nil || *identity.DomainId != services.domainID || identity.Namespace == nil || *identity.Namespace != services.namespace {
		return nil, failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, nativeauth.ErrScope)
	}
	return native, nil
}

func selectForegroundPublisher(ctx context.Context, database *clientstate.Database, services publisherServices, cfg *publisher.Config, guest *clientstate.GuestSession) (func() error, error) {
	cleanup := func() error { return nil }
	if guest != nil {
		route, err := createGuestDemoURL(ctx, services, *cfg)
		if err != nil {
			return nil, err
		}
		cleanupGuest := func() error {
			finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := services.routes.DeletePublicURL(finish, route.Id)
			if errors.Is(err, controlclient.ErrNotFound) {
				return nil
			}
			return err
		}
		native, err := enrollGuestNative(ctx, services, route)
		if err != nil {
			return nil, errors.Join(err, cleanupGuest())
		}
		cfg.Control = guestPublicationControl{publicationControl: nativePublicationControl(native, services.routes), assigned: route, bootstrap: services.routes}
		cfg.PublisherID = native.PublisherID()
		// guest cleanup uses the trial session; its native grant only starts runs.
		return cleanupGuest, nil
	}
	if cfg.Ephemeral {
		if cfg.ServiceProtocol != controlv1.Http {
			return nil, publisherCLIError("temporary publication requires an HTTP service")
		}
		native, err := issuedNativePublisher(ctx, services)
		if err != nil {
			return nil, err
		}
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			return nil, err
		}
		body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: cfg.Target}
		if cfg.AccessMode != "" {
			mode := cfg.AccessMode
			body.AccessMode = &mode
		}
		if cfg.AllowedIPPrefixes != nil {
			prefixes := slices.Clone(cfg.AllowedIPPrefixes)
			body.Ip = &prefixes
		}
		route, err := native.Allocate(ctx, body)
		if err != nil {
			return nil, err
		}
		cfg.Control, cfg.AllocatedPublicURL = nativePublicationControl(native, services.routes), &route
		cfg.PublisherID = native.PublisherID()
		cfg.Hostname, cfg.PublicURLScope, cfg.Purpose = route.CanonicalHostname, route.PublicUrlScope, route.Purpose
		cfg.MembershipID = ""
		if route.MembershipId != nil {
			cfg.MembershipID = *route.MembershipId
		}
		return func() error {
			finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := native.DeletePublicURL(finish, route.Id)
			if errors.Is(err, controlclient.ErrNotFound) {
				return nil
			}
			return err
		}, nil
	}
	reservation := services
	if reservation.publicURLScope == controlv1.Shared {
		reservation.membershipID = ""
	}
	route, err := reserveConfiguredURL(ctx, reservation, *cfg)
	if err != nil {
		return nil, err
	}
	native, _, err := nativeauth.EnsureOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, route)
	if err != nil {
		return nil, err
	}
	if err := native.SelectRoute(route); err != nil {
		return nil, err
	}
	cfg.Control, cfg.PreserveSavedURLTarget = nativePublicationControl(native, services.routes), true
	cfg.PublisherID = native.PublisherID()
	return cleanup, nil
}

func nativeIntegrationConfig(ctx context.Context, database *clientstate.Database, services publisherServices, hostname string, purpose controlv1.PublicURLPurpose, allowed ...[]string) (publisher.Config, error) {
	cfg := integrationURLConfig(services, hostname, purpose)
	if len(allowed) != 0 {
		cfg.AllowedIPPrefixes = slices.Clone(allowed[0])
	}
	lock, err := clientstate.LockHostnameContext(ctx, services.state, hostname)
	if err != nil {
		return cfg, err
	}
	defer lock.Close()
	route, err := services.routes.GetPublicURLByHostname(ctx, services.teamID, hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return cfg, keyErr
		}
		protocol := controlv1.Http
		body := controlv1.CreatePublicURLRequest{TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: hostname, PublicUrlScope: services.publicURLScope, Purpose: purpose, ServiceProtocol: &protocol, Target: integrationURLTarget, AllowedIpPrefixes: &cfg.AllowedIPPrefixes}
		if services.publicURLScope == controlv1.Member {
			body.MembershipId = &services.membershipID
		}
		route, err = services.routes.CreatePublicURL(ctx, body, key)
	}
	if err != nil {
		return cfg, err
	}
	if route.TeamId != services.teamID || route.DomainId != services.domainID || route.CanonicalHostname != hostname || route.Purpose != purpose || route.ServiceProtocol != controlv1.Http || route.Ephemeral || route.LifecycleState != controlv1.Enabled || route.PublicUrlScope != services.publicURLScope {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL differs from the selected project"))
	}
	if route.PublicUrlScope == controlv1.Member && (route.MembershipId == nil || *route.MembershipId != services.membershipID) || route.PublicUrlScope == controlv1.Shared && route.MembershipId != nil {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL belongs to a different membership"))
	}
	// the stored placeholder is public configuration, not a private service.
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	if route.Target != integrationURLTarget || !slices.Equal(currentPolicy, cfg.AllowedIPPrefixes) {
		route, err = services.routes.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{Target: integrationURLTarget, AllowedIpPrefixes: cfg.AllowedIPPrefixes})
		if err != nil {
			return cfg, err
		}
	}
	native, _, err := nativeauth.EnsureOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, route)
	if err != nil {
		return cfg, err
	}
	if err := native.SelectRoute(route); err != nil {
		return cfg, err
	}
	cfg.Control, cfg.PreserveSavedURLTarget = nativePublicationControl(native, services.routes), true
	cfg.PublisherID = native.PublisherID()
	return cfg, nil
}
