package invocation

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

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
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
