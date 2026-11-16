package invocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// reserveConfiguredService uses management authority for one exact saved HTTP
// service. the declaration is ordinary service intent, not a runtime config or
// a synthetic project binding. declaration is complete desired intent. an
// optional selector rebuilds it from current configuration for a partial update;
// nil retains it unchanged. selection never performs remote setup. this operation
// owns scope checks, current reads, declaration CAS, and recovery on one ID.
func reserveConfiguredService(ctx context.Context, services publisherServices, declaration controlv1.ProjectServiceConfiguration, selectIntent ...func(controlv1.Service, *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error)) (_ controlv1.Service, result error) {
	if services.authenticated == nil || services.routes == nil || services.state == nil || services.ephemeral ||
		services.teamID == "" || services.domainID == "" || services.hostname == "" ||
		len(selectIntent) > 1 || len(selectIntent) == 1 && selectIntent[0] == nil {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	digest := sha256.Sum256([]byte(services.authenticated.ServerEndpoint + "\x00" + services.teamID + "\x00" + services.domainID + "\x00" + services.hostname))
	name := "service-" + hex.EncodeToString(digest[:12])
	normalize := func(desired controlv1.ProjectServiceConfiguration) (controlv1.ProjectServiceConfiguration, *targettrust.Snapshot, error) {
		if desired.Protocol != nil && *desired.Protocol != controlv1.ServiceProtocolHTTP ||
			desired.Ephemeral != nil && *desired.Ephemeral ||
			desired.Hostname != nil && *desired.Hostname != services.hostname ||
			desired.DomainId != nil && *desired.DomainId != services.domainID {
			return desired, nil, publisheridentity.ErrScope
		}
		desired.Name, desired.DomainId, desired.Hostname = &name, &services.domainID, &services.hostname
		desired.Protocol, desired.Ephemeral, desired.Public = new(controlv1.ServiceProtocolHTTP), new(false), new(true)
		var trust *targettrust.Snapshot
		if tls := desired.TargetTls; tls != nil {
			pem := ""
			if tls.CaPem != nil {
				pem = *tls.CaPem
			}
			captured, err := targettrust.NewDeclaration(tls.Hostname, []byte(pem))
			if err != nil {
				return desired, nil, err
			}
			if tls.Digest != "" && tls.Digest != captured.Digest {
				return desired, nil, publisheridentity.ErrScope
			}
			trust, err = captured.Snapshot()
			if err != nil {
				return desired, nil, err
			}
		}
		return desired, trust, nil
	}
	declaration, trust, err := normalize(declaration)
	if err != nil {
		return controlv1.Service{}, err
	}
	check := func(saved controlv1.Service) error {
		if !opaqueid.Valid(saved.Id, opaqueid.ServicePrefix) || saved.TeamId != services.teamID || saved.Name != name || saved.DomainId == nil || *saved.DomainId != services.domainID ||
			!saved.Enabled || saved.Ephemeral || saved.Source != nil || saved.Endpoint == nil || saved.Protocol != controlv1.ServiceProtocolHTTP ||
			saved.Placement != nil && saved.Placement.WorktreeKey != nil ||
			saved.Endpoint.Hostname != services.hostname || saved.Endpoint.Port != 443 || !saved.Endpoint.Public {
			return failure.Wrap("reserve project service", failure.ServerResponseInvalid, errors.New("saved service differs from the exact selected endpoint"))
		}
		return nil
	}
	approved := func(saved controlv1.Service, desired controlv1.ProjectServiceConfiguration, trust *targettrust.Snapshot) (controlv1.Service, error) {
		if err := check(saved); err != nil {
			return controlv1.Service{}, err
		}
		if err := publisheridentity.MatchServiceDeclaration(saved, "http", trust); err != nil {
			return controlv1.Service{}, err
		}
		if desired.RequirePostQuantum != nil && saved.RequirePostQuantum != *desired.RequirePostQuantum {
			return controlv1.Service{}, publisheridentity.ErrScope
		}
		return saved, nil
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return controlv1.Service{}, err
	}
	var current controlv1.Service
	var created bool
	// control atomically creates or recovers the exact service. retain one
	// request key through lost replies; no local lock or inventory can prove
	// that an uncertain remote mutation did not commit.
	for range 3 {
		current, created, err = services.routes.ReserveServiceAt(ctx, services.teamID, name, key,
			&controlv1.ServicePlacement{DomainId: &services.domainID, Hostname: &services.hostname},
			controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TargetTls: publisheridentity.ServiceTargetTLS(trust)}, &declaration)
		if err == nil {
			break
		}
		if !retryServiceReservation(ctx, err) {
			return controlv1.Service{}, err
		}
	}
	if err != nil {
		return controlv1.Service{}, err
	}
	if err := check(current); err != nil {
		return controlv1.Service{}, err
	}
	if created {
		return approved(current, declaration, trust)
	}
	for attempt := 0; attempt < 3; attempt++ {
		desired, desiredTrust := declaration, trust
		var configurationDigest *string
		if len(selectIntent) != 0 {
			configured, digest, readErr := services.routes.GetServiceConfiguration(ctx, current.Id)
			if readErr != nil {
				return controlv1.Service{}, readErr
			}
			selected, selectErr := selectIntent[0](current, configured)
			if selectErr != nil {
				return controlv1.Service{}, selectErr
			}
			if selected == nil {
				return current, nil
			}
			desired, desiredTrust, selectErr = normalize(*selected)
			if selectErr != nil {
				return controlv1.Service{}, selectErr
			}
			if configured != nil && reflect.DeepEqual(*configured, desired) {
				return approved(current, desired, desiredTrust)
			}
			configurationDigest = &digest
		}
		saved, updateErr := services.routes.ConfigureService(ctx, current.Id, controlv1.UpdateServiceRequest{
			ExpectedTrustRevision: current.TrustRevision, ExpectedConfigurationDigest: configurationDigest,
			ExpectedPublisherPool: new(current.PublisherPool),
			Protocol:              controlv1.ServiceProtocolHTTP, TargetTls: publisheridentity.ServiceTargetTLS(desiredTrust),
			PublisherPool: current.PublisherPool, Configuration: &desired})
		if updateErr == nil {
			if saved.Id != current.Id || saved.PublisherPool != current.PublisherPool {
				return controlv1.Service{}, publisheridentity.ErrScope
			}
			return approved(saved, desired, desiredTrust)
		}
		err = updateErr
		if !retryServiceReservation(ctx, err) {
			return controlv1.Service{}, err
		}
		// control owns declaration equality and no-op policy changes. reread
		// after conflict or response loss, then retry on the same service ID.
		selectedID := current.Id
		current, updateErr = services.routes.GetService(ctx, selectedID)
		if updateErr == nil && current.Id != selectedID {
			updateErr = publisheridentity.ErrScope
		}
		if updateErr == nil {
			updateErr = check(current)
		}
		if updateErr != nil {
			return controlv1.Service{}, errors.Join(err, updateErr)
		}
	}
	return controlv1.Service{}, err
}

func retryServiceReservation(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	reason, _ := failure.ReasonOf(err)
	return reason == failure.ServerConflict || reason == failure.ServerUnavailable
}

func selectNativeProjectPublisher(ctx context.Context, services publisherServices, declaration controlv1.ProjectServiceConfiguration, selectIntent ...func(controlv1.Service, *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error)) (*publisheridentity.Native, controlv1.Service, error) {
	saved, err := reserveConfiguredService(ctx, services, declaration, selectIntent...)
	if err != nil {
		return nil, controlv1.Service{}, err
	}
	native, _, err := publisheridentity.EnsureServiceOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, saved)
	return native, saved, err
}
