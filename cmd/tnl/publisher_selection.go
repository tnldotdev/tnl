package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func protocolForService(service config.Service) controlv1.PublicURLServiceProtocol {
	return controlv1.PublicURLServiceProtocol(config.Protocol(service))
}

// reserveConfiguredURL uses team authority only to create or edit saved state.
// targets stay private to the native owner for both HTTP and TCP publications.
func reserveConfiguredURL(ctx context.Context, services publisherServices, cfg publisher.Config) (controlv1.PublicURL, error) {
	// an unchanged saved URL can be read while its publisher holds the
	// hostname lock. only creation and edits need exclusive access.
	route, err := services.routes.GetPublicURLByHostname(ctx, services.teamID, cfg.Hostname)
	if err == nil {
		prefixes, checkErr := checkedConfiguredURL(route, services, cfg)
		if checkErr != nil {
			return controlv1.PublicURL{}, checkErr
		}
		if route.Target == "" && slices.Equal(prefixes, cfg.AllowedIPPrefixes) {
			return route, nil
		}
	} else if !errors.Is(err, controlclient.ErrNotFound) {
		return route, err
	}
	lock, err := clientstate.LockHostnameContext(ctx, services.state, cfg.Hostname)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	defer lock.Close()
	route, err = services.routes.GetPublicURLByHostname(ctx, services.teamID, cfg.Hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return route, keyErr
		}
		protocol := cfg.ServiceProtocol
		if protocol == "" {
			protocol = "http"
		}
		body := controlv1.CreatePublicURLRequest{TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: cfg.Hostname, PublicUrlScope: services.publicURLScope, Purpose: controlv1.App, ServiceProtocol: &protocol, AllowedIpPrefixes: &cfg.AllowedIPPrefixes}
		if services.publicURLScope == controlv1.Member && services.membershipID != "" {
			body.MembershipId = &services.membershipID
		}
		route, err = services.routes.CreatePublicURL(ctx, body, key)
	}
	if err != nil {
		return route, err
	}
	prefixes, err := checkedConfiguredURL(route, services, cfg)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	if route.Target != "" || !slices.Equal(prefixes, cfg.AllowedIPPrefixes) {
		return services.routes.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{Target: "", AllowedIpPrefixes: slices.Clone(cfg.AllowedIPPrefixes)})
	}
	return route, nil
}

func checkedConfiguredURL(route controlv1.PublicURL, services publisherServices, cfg publisher.Config) ([]string, error) {
	if route.TeamId != services.teamID || route.DomainId != services.domainID || route.CanonicalHostname != cfg.Hostname || route.Purpose != controlv1.App || route.ServiceProtocol != cfg.ServiceProtocol || route.Ephemeral || route.LifecycleState != controlv1.Enabled || route.PublicUrlScope != services.publicURLScope ||
		services.publicURLScope == controlv1.Member && (route.MembershipId == nil || *route.MembershipId != services.membershipID) || services.publicURLScope == controlv1.Shared && route.MembershipId != nil {
		return nil, failure.Wrap("reserve project public URL", failure.ServerResponseInvalid, errors.New("saved public URL differs from the selected service"))
	}
	prefixes := []string{}
	if route.AllowedIpPrefixes != nil {
		prefixes = *route.AllowedIpPrefixes
	}
	return prefixes, nil
}

func selectNativeProjectPublisher(ctx context.Context, database *clientstate.Database, services publisherServices, cfg publisher.Config) (*nativeauth.Native, error) {
	route, err := reserveConfiguredURL(ctx, services, cfg)
	if err != nil {
		return nil, err
	}
	server := services.authenticated.ServerEndpoint
	digest := sha256.Sum256([]byte(server + "\x00" + route.Id))
	scope := "project-publisher:" + hex.EncodeToString(digest[:])
	lock, err := services.state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	control, err := controlclient.New(server, nil, "")
	if err != nil {
		return nil, err
	}
	authority, err := authorityclient.New(server, nil, "")
	if err != nil {
		return nil, err
	}
	var native *nativeauth.Native
	if reference, found, err := database.SystemState(ctx, scope); err != nil {
		return nil, err
	} else if found {
		native, _, err = nativeauth.LoadNative(ctx, services.state, control, authority, string(reference))
		if err != nil {
			return nil, err
		}
	} else {
		enrollment, err := services.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: route.TeamId, PublicUrlId: &route.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "project-owner"})
		if err != nil {
			return nil, err
		}
		var identityID string
		native, identity, err := nativeauth.EnrollNative(ctx, services.state, control, authority, enrollment.EnrollmentKey)
		if err != nil {
			return nil, err
		}
		identityID = identity.ClientId
		if err := database.SaveSystemState(ctx, scope, []byte(identityID)); err != nil {
			return nil, err
		}
		if err := native.SelectRoute(route); err != nil {
			return nil, err
		}
		return native, nil
	}
	if err := native.SelectRoute(route); err != nil {
		return nil, err
	}
	return native, nil
}
