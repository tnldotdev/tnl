package publisher

import (
	"context"
	"errors"
	"fmt"
	"slices"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func createOrLoadPublicURL(ctx context.Context, config Config) (controlv1.PublicURL, bool, error) {
	if config.AllocatedPublicURL != nil {
		route := *config.AllocatedPublicURL
		if !config.Ephemeral || !route.Ephemeral || route.LifecycleState != controlv1.Enabled ||
			(config.ServiceProtocol != "" && config.ServiceProtocol != controlv1.Http) ||
			route.Target != config.Target || route.Purpose != controlv1.App {
			return controlv1.PublicURL{}, false, errors.New("publisher: allocated ad-hoc public URL does not match its target")
		}
		if err := validateRouteIdentity(route, config); err != nil {
			return controlv1.PublicURL{}, false, err
		}
		return route, false, nil
	}
	if !config.Purpose.Valid() {
		return controlv1.PublicURL{}, false, errors.New("publisher: public URL purpose is required")
	}
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(config.AllowedIPPrefixes)
	if err != nil {
		return controlv1.PublicURL{}, false, fmt.Errorf("publisher: invalid allowed IP prefixes: %w", err)
	}
	config.AllowedIPPrefixes = allowedIPPrefixes
	if !config.Ephemeral {
		route, err := config.Control.GetPublicURLByHostname(ctx, config.TeamID, config.Hostname)
		if err != nil && !errors.Is(err, controlclient.ErrNotFound) {
			return controlv1.PublicURL{}, false, err
		}
		if err == nil {
			if err := validateRouteIdentity(route, config); err != nil {
				return controlv1.PublicURL{}, false, err
			}
			reconciled, err := reconcilePublicURL(ctx, config, route)
			return reconciled, false, err
		}
	}
	idempotencyKey, err := opaqueID(opaqueid.IdempotencyPrefix)
	if err != nil {
		return controlv1.PublicURL{}, false, err
	}
	body := controlv1.CreatePublicURLRequest{
		TeamId: config.TeamID, DomainId: config.DomainID, CanonicalHostname: config.Hostname,
		PublicUrlScope: config.PublicURLScope, Purpose: config.Purpose,
	}
	integration := config.Purpose == controlv1.Oauth || config.Purpose == controlv1.Webhooks
	if integration {
		mode := controlv1.Anonymous
		body.AccessMode = &mode
	} else if config.AccessMode != "" {
		mode := config.AccessMode
		body.AccessMode = &mode
	}
	body.Target = config.Target
	if config.PublicURLScope == controlv1.Member && config.MembershipID != "" {
		body.MembershipId = &config.MembershipID
	}
	if config.AllowedIPPrefixes != nil {
		allowed := slices.Clone(config.AllowedIPPrefixes)
		body.AllowedIpPrefixes = &allowed
	}
	if config.Ephemeral {
		body.Ephemeral = &config.Ephemeral
	}
	route, err := config.Control.CreatePublicURL(ctx, body, idempotencyKey)
	return route, err == nil, classifyPublicURLConflict(err)
}

func validateRouteIdentity(route controlv1.PublicURL, config Config) error {
	if route.CanonicalHostname != config.Hostname || route.TeamId != config.TeamID || route.DomainId != config.DomainID || route.PublicUrlScope != config.PublicURLScope || route.Purpose != config.Purpose ||
		route.Ephemeral != config.Ephemeral {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	if route.ServiceProtocol != "" && route.ServiceProtocol != controlv1.Http {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL protocol is not HTTP"))
	}
	if config.PublicURLScope == controlv1.Member {
		if route.MembershipId == nil || *route.MembershipId != config.MembershipID {
			return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
		}
	} else if route.MembershipId != nil {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	return nil
}

func reconcilePublicURL(ctx context.Context, config Config, route controlv1.PublicURL) (controlv1.PublicURL, error) {
	if route.LifecycleState != controlv1.Enabled {
		return controlv1.PublicURL{}, diagnostic.Wrap(
			diagnostic.PublicURLConflict,
			fmt.Errorf("publisher: public URL %s is not enabled", route.Id),
		)
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	desiredPolicy := config.AllowedIPPrefixes
	integration := config.Purpose == controlv1.Oauth || config.Purpose == controlv1.Webhooks
	if (desiredPolicy == nil || config.AccessMode != "") && !integration {
		// a saved public URL retains live access edits when project config omits
		// access. a configured mode is reconciled separately below.
		desiredPolicy = slices.Clone(currentPolicy)
	}
	if !integration && config.AccessMode != "" && (route.AccessMode != config.AccessMode || !slices.Equal(currentPolicy, config.AllowedIPPrefixes)) {
		client, ok := config.Control.(interface {
			ReplaceVisitorAccess(context.Context, string, controlv1.ReplaceVisitorAccessRequest) (controlv1.PublicURL, error)
		})
		if !ok {
			return controlv1.PublicURL{}, errors.New("publisher: current visitor policy client is required")
		}
		updated, err := client.ReplaceVisitorAccess(ctx, route.Id, controlv1.ReplaceVisitorAccessRequest{
			Mode: config.AccessMode, Ip: append([]string{}, config.AllowedIPPrefixes...), ExpectedRevision: route.MutationRevision,
		})
		if err != nil {
			return controlv1.PublicURL{}, err
		}
		route = updated
		currentPolicy = slices.Clone(config.AllowedIPPrefixes)
		desiredPolicy = slices.Clone(currentPolicy)
	}
	if !slices.Equal(currentPolicy, desiredPolicy) {
		updated, err := config.Control.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{
			Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
		})
		return updated, classifyPublicURLConflict(err)
	}
	if config.PreserveSavedURLTarget && route.Target == "" {
		return route, nil
	}
	if route.Target == config.Target {
		return route, nil
	}
	updated, err := config.Control.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{
		Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
	})
	return updated, classifyPublicURLConflict(err)
}

func classifyPublicURLConflict(err error) error {
	if errors.Is(err, controlclient.ErrNameUnavailable) || errors.Is(err, controlclient.ErrStatusConflict) {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, err)
	}
	return err
}

func opaqueID(prefix string) (string, error) {
	id, err := opaqueid.New(prefix)
	if err != nil {
		return "", fmt.Errorf("publisher: generate idempotency key: %w", err)
	}
	return id, nil
}
