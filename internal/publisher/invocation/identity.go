package invocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func protocolForService(service config.Service) controlv1.PublicURLServiceProtocol {
	return controlv1.PublicURLServiceProtocol(config.Protocol(service))
}

func ProjectPublisherScope(server, publicURLID string) string {
	digest := sha256.Sum256([]byte(server + "\x00" + publicURLID))
	return "project-publisher:" + hex.EncodeToString(digest[:])
}

// reserveConfiguredURL uses team authority only to create or edit saved state.
// HTTP app and alias targets stay private to the native owner.
func reserveConfiguredURL(ctx context.Context, services publisherServices, cfg publisher.Config) (controlv1.PublicURL, error) {
	if cfg.Purpose != controlv1.App && cfg.Purpose != controlv1.Alias || cfg.Ephemeral || cfg.ServiceProtocol != controlv1.Http {
		return controlv1.PublicURL{}, publisherCLIError("project publications require a saved HTTP app or alias public URL")
	}
	// an unchanged saved URL can be read while its publisher holds the
	// hostname lock. only creation and edits need exclusive access.
	publicURL, err := services.routes.GetPublicURLByHostname(ctx, services.teamID, cfg.Hostname)
	if err == nil {
		prefixes, checkErr := checkedConfiguredURL(publicURL, services, cfg)
		if checkErr != nil {
			return controlv1.PublicURL{}, checkErr
		}
		if publicURL.Target == "" && configuredURLAccessMatches(publicURL, prefixes, cfg) {
			return publicURL, nil
		}
	} else if !errors.Is(err, clientcontrol.ErrNotFound) {
		return publicURL, err
	}
	lock, err := clientstate.LockHostnameContext(ctx, services.state, cfg.Hostname)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	defer lock.Close()
	publicURL, err = services.routes.GetPublicURLByHostname(ctx, services.teamID, cfg.Hostname)
	if errors.Is(err, clientcontrol.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return publicURL, keyErr
		}
		protocol := cfg.ServiceProtocol
		body := controlv1.CreatePublicURLRequest{TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: cfg.Hostname, PublicUrlScope: services.publicURLScope, Purpose: cfg.Purpose, ServiceProtocol: &protocol, AllowedIpPrefixes: &cfg.AllowedIPPrefixes}
		if cfg.AccessMode != "" {
			mode := cfg.AccessMode
			body.AccessMode = &mode
		}
		if services.publicURLScope == controlv1.Member && services.membershipID != "" {
			body.MembershipId = &services.membershipID
		}
		publicURL, err = services.routes.CreatePublicURL(ctx, body, key)
	}
	if err != nil {
		return publicURL, err
	}
	prefixes, err := checkedConfiguredURL(publicURL, services, cfg)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	if cfg.AccessMode != "" && (publicURL.AccessMode != cfg.AccessMode || !slices.Equal(prefixes, cfg.AllowedIPPrefixes)) {
		publicURL, err = services.routes.ReplaceVisitorAccess(ctx, publicURL.Id, controlv1.ReplaceVisitorAccessRequest{
			Mode: cfg.AccessMode, Ip: append([]string{}, cfg.AllowedIPPrefixes...), ExpectedRevision: publicURL.MutationRevision,
		})
		if err != nil {
			return controlv1.PublicURL{}, err
		}
		prefixes = cfg.AllowedIPPrefixes
	}
	if publicURL.Target != "" || cfg.AccessMode == "" && cfg.AllowedIPPrefixes != nil && !slices.Equal(prefixes, cfg.AllowedIPPrefixes) {
		if cfg.AccessMode == "" && cfg.AllowedIPPrefixes != nil {
			prefixes = cfg.AllowedIPPrefixes
		}
		return services.routes.UpdatePublicURL(ctx, publicURL.Id, controlv1.UpdatePublicURLRequest{Target: "", AllowedIpPrefixes: slices.Clone(prefixes)})
	}
	return publicURL, nil
}

func configuredURLAccessMatches(publicURL controlv1.PublicURL, prefixes []string, cfg publisher.Config) bool {
	if cfg.AccessMode != "" {
		return publicURL.AccessMode == cfg.AccessMode && slices.Equal(prefixes, cfg.AllowedIPPrefixes)
	}
	return cfg.AllowedIPPrefixes == nil || slices.Equal(prefixes, cfg.AllowedIPPrefixes)
}

func checkedConfiguredURL(publicURL controlv1.PublicURL, services publisherServices, cfg publisher.Config) ([]string, error) {
	if publicURL.TeamId != services.teamID || publicURL.DomainId != services.domainID || publicURL.CanonicalHostname != cfg.Hostname || publicURL.Purpose != cfg.Purpose || publicURL.ServiceProtocol != cfg.ServiceProtocol || publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled || publicURL.PublicUrlScope != services.publicURLScope ||
		services.publicURLScope == controlv1.Member && (publicURL.MembershipId == nil || *publicURL.MembershipId != services.membershipID) || services.publicURLScope == controlv1.Shared && publicURL.MembershipId != nil {
		return nil, failure.Wrap("reserve project public URL", failure.ServerResponseInvalid, errors.New("saved public URL differs from the selected service"))
	}
	prefixes := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		prefixes = *publicURL.AllowedIpPrefixes
	}
	return prefixes, nil
}

func selectNativeProjectPublisher(ctx context.Context, services publisherServices, cfg publisher.Config) (*publisheridentity.Native, error) {
	publicURL, err := reserveConfiguredURL(ctx, services, cfg)
	if err != nil {
		return nil, err
	}
	server := services.authenticated.ServerEndpoint
	scope := ProjectPublisherScope(server, publicURL.Id)
	lock, err := services.state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	control, err := clientcontrol.New(server, nil, "")
	if err != nil {
		return nil, err
	}
	authority, err := clientauthority.New(server, nil, "")
	if err != nil {
		return nil, err
	}
	var native *publisheridentity.Native
	if selected, found, err := services.state.SelectedPublisherIdentity(ctx, "project", scope); err != nil {
		return nil, err
	} else if found {
		native, _, err = publisheridentity.LoadNative(ctx, services.state, control, authority, selected.ID)
		if err != nil {
			return nil, err
		}
	} else {
		enrollment, err := services.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: publicURL.TeamId, PublicUrlId: &publicURL.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "project-owner"})
		if err != nil {
			return nil, err
		}
		native, identity, err := publisheridentity.EnrollNative(ctx, services.state, control, authority, enrollment.EnrollmentKey)
		if err != nil {
			return nil, err
		}
		if err := services.state.SelectPublisherIdentity(ctx, "project", scope, identity.ClientId); err != nil {
			return nil, err
		}
		if err := native.SelectPublicURL(publicURL); err != nil {
			return nil, err
		}
		return native, nil
	}
	if err := native.SelectPublicURL(publicURL); err != nil {
		return nil, err
	}
	return native, nil
}
