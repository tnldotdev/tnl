package publisher

import (
	"context"
	"errors"
	"fmt"
	"slices"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func createOrLoadPublicURL(ctx context.Context, config Config) (controlv1.PublicURL, bool, error) {
	if config.AssignedPublicURL != nil {
		publicURL := *config.AssignedPublicURL
		if config.Ephemeral != publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled ||
			(config.ServiceProtocol != "" && config.ServiceProtocol != controlv1.Http) ||
			(config.Ephemeral && publicURL.Target != config.Target) {
			return controlv1.PublicURL{}, false, errors.New("publisher: allocated ad-hoc public URL does not match its target")
		}
		if err := validateRouteIdentity(publicURL, config); err != nil {
			return controlv1.PublicURL{}, false, err
		}
		return publicURL, false, nil
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
		publicURL, err := config.Control.GetPublicURLByHostname(ctx, config.TeamID, config.Hostname)
		if err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
			return controlv1.PublicURL{}, false, err
		}
		if err == nil {
			if err := validateRouteIdentity(publicURL, config); err != nil {
				return controlv1.PublicURL{}, false, err
			}
			reconciled, err := reconcilePublicURL(ctx, config, publicURL)
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
	management, ok := config.Control.(PublicURLManagementClient)
	if !ok {
		return controlv1.PublicURL{}, false, failure.Wrap("create saved public URL", failure.PublisherGrantMismatch, errors.New("publisher grant does not permit public URL management"))
	}
	publicURL, err := management.CreatePublicURL(ctx, body, idempotencyKey)
	return publicURL, err == nil, classifyPublicURLConflict(err)
}

func validateRouteIdentity(publicURL controlv1.PublicURL, config Config) error {
	if publicURL.CanonicalHostname != config.Hostname || publicURL.TeamId != config.TeamID || publicURL.DomainId != config.DomainID || publicURL.PublicUrlScope != config.PublicURLScope || publicURL.Purpose != config.Purpose ||
		publicURL.Ephemeral != config.Ephemeral {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	if publicURL.ServiceProtocol != "" && publicURL.ServiceProtocol != controlv1.Http {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL protocol is not HTTP"))
	}
	if config.PublicURLScope == controlv1.Member {
		if publicURL.MembershipId == nil || *publicURL.MembershipId != config.MembershipID {
			return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
		}
	} else if publicURL.MembershipId != nil {
		return diagnostic.Wrap(diagnostic.PublicURLConflict, errors.New("publisher: existing public URL identity does not match the requested public URL"))
	}
	return nil
}

func reconcilePublicURL(ctx context.Context, config Config, publicURL controlv1.PublicURL) (controlv1.PublicURL, error) {
	if publicURL.LifecycleState != controlv1.Enabled {
		return controlv1.PublicURL{}, diagnostic.Wrap(
			diagnostic.PublicURLConflict,
			fmt.Errorf("publisher: public URL %s is not enabled", publicURL.Id),
		)
	}
	currentPolicy := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		currentPolicy = *publicURL.AllowedIpPrefixes
	}
	desiredPolicy := config.AllowedIPPrefixes
	integration := config.Purpose == controlv1.Oauth || config.Purpose == controlv1.Webhooks
	if (desiredPolicy == nil || config.AccessMode != "") && !integration {
		// a saved public URL retains live access edits when project config omits
		// access. a configured mode is reconciled separately below.
		desiredPolicy = slices.Clone(currentPolicy)
	}
	if !integration && config.AccessMode != "" && (publicURL.AccessMode != config.AccessMode || !slices.Equal(currentPolicy, config.AllowedIPPrefixes)) {
		client, ok := config.Control.(interface {
			ReplaceVisitorAccess(context.Context, string, controlv1.ReplaceVisitorAccessRequest) (controlv1.PublicURL, error)
		})
		if !ok {
			return controlv1.PublicURL{}, errors.New("publisher: current visitor policy client is required")
		}
		updated, err := client.ReplaceVisitorAccess(ctx, publicURL.Id, controlv1.ReplaceVisitorAccessRequest{
			Mode: config.AccessMode, Ip: append([]string{}, config.AllowedIPPrefixes...), ExpectedRevision: publicURL.MutationRevision,
		})
		if err != nil {
			return controlv1.PublicURL{}, err
		}
		publicURL = updated
		currentPolicy = slices.Clone(config.AllowedIPPrefixes)
		desiredPolicy = slices.Clone(currentPolicy)
	}
	if !slices.Equal(currentPolicy, desiredPolicy) {
		management, ok := config.Control.(PublicURLManagementClient)
		if !ok {
			return controlv1.PublicURL{}, failure.Wrap("edit saved public URL", failure.PublisherGrantMismatch, errors.New("publisher grant does not permit public URL management"))
		}
		updated, err := management.UpdatePublicURL(ctx, publicURL.Id, controlv1.UpdatePublicURLRequest{
			Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
		})
		return updated, classifyPublicURLConflict(err)
	}
	if config.PreserveSavedPublicURLTarget && publicURL.Target == "" {
		return publicURL, nil
	}
	if publicURL.Target == config.Target {
		return publicURL, nil
	}
	management, ok := config.Control.(PublicURLManagementClient)
	if !ok {
		return controlv1.PublicURL{}, failure.Wrap("edit saved public URL", failure.PublisherGrantMismatch, errors.New("publisher grant does not permit public URL management"))
	}
	updated, err := management.UpdatePublicURL(ctx, publicURL.Id, controlv1.UpdatePublicURLRequest{
		Target: config.Target, AllowedIpPrefixes: slices.Clone(desiredPolicy),
	})
	return updated, classifyPublicURLConflict(err)
}

func classifyPublicURLConflict(err error) error {
	if errors.Is(err, clientcontrol.ErrNameUnavailable) || errors.Is(err, clientcontrol.ErrStatusConflict) {
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
