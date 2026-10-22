package invocation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func guestForDemo(
	ctx context.Context, state *clientstate.Database, serverURL string, flags PublicOptions,
) (*clientstate.GuestSession, error) {
	control, err := clientcontrol.New(serverURL, nil, "")
	if err != nil {
		return nil, err
	}
	return guestForDemoWithControl(ctx, state, serverURL, flags, control)
}

type guestDemoControlClient interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
	CreateGuestDemo(context.Context) (controlv1.GuestDemoSession, error)
}

func guestForDemoWithControl(
	ctx context.Context, state *clientstate.Database, serverURL string, flags PublicOptions,
	control guestDemoControlClient,
) (*clientstate.GuestSession, error) {
	if flags.AccessToken != "" {
		return nil, nil
	}
	store, err := state.Server(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	lock, err := clientstate.LockGuestSessionContext(ctx, store)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, found, err := store.ControlSession(ctx); err != nil || found {
		return nil, err
	}
	discovery, err := control.Discovery(ctx)
	if err != nil || !discovery.GuestDemo {
		return nil, err
	}
	if flags.Team != "" || flags.Domain != "" || flags.Anonymous || len(flags.IP) != 0 {
		return nil, failure.Wrap("validate guest demo options", failure.GuestDemoOnly, errors.New("guest demos use their assigned namespace and visitor link; run tnl auth login to change access settings"))
	}
	guest, found, err := store.GuestSession(ctx)
	if err != nil {
		return nil, err
	}
	if found && !guest.ExpiresAt.After(time.Now()) {
		if err := store.RemoveGuestSession(ctx); err != nil {
			return nil, err
		}
		found = false
	}
	if !found {
		issued, err := control.CreateGuestDemo(ctx)
		if err != nil {
			return nil, fmt.Errorf("start guest demo: %w", err)
		}
		guest = clientstate.GuestSession{
			GuestID: issued.GuestId, AccessToken: issued.AccessToken, TeamID: issued.TeamId,
			MembershipID: issued.MembershipId, DomainID: issued.DomainId,
			Namespace: issued.Namespace,
			ExpiresAt: issued.ExpiresAt,
		}
		if err := store.SaveGuestSession(ctx, guest); err != nil {
			return nil, err
		}
	}
	return &guest, nil
}

func guestPublisherServices(
	ctx context.Context, state *clientstate.Database, serverURL, hostname string,
	guest clientstate.GuestSession, routes *clientcontrol.Client,
) (publisherServices, error) {
	store, err := state.Server(ctx, serverURL)
	if err != nil {
		return publisherServices{}, err
	}
	return publisherServices{
		state: store, hostname: hostname + "." + guest.Namespace, namespace: guest.Namespace,
		teamID: guest.TeamID, membershipID: guest.MembershipID, domainID: guest.DomainID,
		publicURLScope: controlv1.Member, policyRevision: 1, ephemeral: true, routes: routes,
	}, nil
}

func createGuestDemoURL(ctx context.Context, services publisherServices, cfg publisher.Config) (controlv1.PublicURL, error) {
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	protocol, ephemeral := controlv1.Http, true
	publicURL, err := services.routes.CreatePublicURL(ctx, controlv1.CreatePublicURLRequest{
		TeamId: services.teamID, MembershipId: &services.membershipID, DomainId: services.domainID,
		CanonicalHostname: services.hostname, Purpose: controlv1.Demo, PublicUrlScope: controlv1.Member,
		ServiceProtocol: &protocol, Target: cfg.Target, AllowedIpPrefixes: &cfg.AllowedIPPrefixes, Ephemeral: &ephemeral,
	}, key)
	if err != nil {
		return publicURL, err
	}
	prefixes := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		prefixes = *publicURL.AllowedIpPrefixes
	}
	if publicURL.TeamId != services.teamID || publicURL.DomainId != services.domainID || publicURL.CanonicalHostname != services.hostname || publicURL.Purpose != controlv1.Demo || publicURL.ServiceProtocol != controlv1.Http || publicURL.PublicUrlScope != controlv1.Member || publicURL.MembershipId == nil || *publicURL.MembershipId != services.membershipID || !publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled || publicURL.Target != cfg.Target || len(prefixes) != 1 || !slices.Equal(prefixes, cfg.AllowedIPPrefixes) {
		return controlv1.PublicURL{}, failure.Wrap("assign guest demo URL", failure.ServerResponseInvalid, errors.New("control returned a different guest demo URL or source IP policy"))
	}
	return publicURL, nil
}

// the guest session may assign a demo URL, but every run uses its own key and
// URL-scoped trial grant. the server checks the original guest source IP.
func enrollGuestNative(ctx context.Context, services publisherServices, publicURL controlv1.PublicURL) (*publisheridentity.Native, error) {
	control, err := clientcontrol.New(services.routes.ControlURL(), nil, "")
	if err != nil {
		return nil, err
	}
	authority, err := clientauthority.New(services.routes.ControlURL(), nil, "")
	if err != nil {
		return nil, err
	}
	return enrollGuestNativeWithClients(ctx, services.state, publicURL, services.routes, control, authority)
}

type guestEnrollmentClient interface {
	EnrollGuestPublisher(context.Context, string, ed25519.PublicKey) (controlv1.GuestPublisherIdentity, error)
}

func enrollGuestNativeWithClients(ctx context.Context, store *clientstate.Store, publicURL controlv1.PublicURL, bootstrap guestEnrollmentClient, control publisheridentity.NativeControl, authority publisheridentity.AssertionExchanger) (*publisheridentity.Native, error) {
	scope := "guest-publisher:" + publicURL.Id
	lock, err := store.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	saved, found, err := store.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return nil, err
	}
	if found {
		native, _, err := publisheridentity.LoadNative(ctx, store, control, authority, saved.ID)
		if err != nil {
			return nil, err
		}
		return native, native.SelectPublicURL(publicURL)
	}
	pending, found, err := store.PendingPublisherEnrollmentForSelection(ctx, "project", scope)
	if err != nil {
		return nil, err
	}
	if !found {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pending = clientstate.PendingPublisherEnrollment{EnrollmentID: publicURL.Id, SelectionKind: "project", SelectionKey: scope, PublicKey: public, SigningKey: private, ExpiresAt: time.Now().Add(24 * time.Hour)}
		if err := store.SavePendingPublisherEnrollment(ctx, pending); err != nil {
			return nil, err
		}
	}
	if len(pending.SigningKey) != ed25519.PrivateKeySize || !pending.ExpiresAt.After(time.Now()) {
		return nil, publisheridentity.ErrScope
	}
	private := ed25519.PrivateKey(pending.SigningKey)
	if !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) || !private.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pending.PublicKey)) {
		return nil, publisheridentity.ErrScope
	}
	var identity authorityv1.PublisherEnrollmentResult
	if len(pending.ResultJSON) != 0 {
		if err := json.Unmarshal(pending.ResultJSON, &identity); err != nil {
			return nil, err
		}
	} else {
		issued, err := bootstrap.EnrollGuestPublisher(ctx, publicURL.Id, private.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		if issued.PublicUrlId != publicURL.Id || issued.TeamId != publicURL.TeamId {
			return nil, failure.Wrap("enroll guest publisher", failure.ServerResponseInvalid, publisheridentity.ErrScope)
		}
		identity = authorityv1.PublisherEnrollmentResult{ClientId: issued.ClientId, KeyId: issued.KeyId, GrantId: issued.GrantId, TeamId: issued.TeamId, PublicUrlId: &issued.PublicUrlId, Kind: authorityv1.SavedPublicUrl}
		pending.ResultJSON, err = json.Marshal(identity)
		if err != nil {
			return nil, err
		}
	}
	native, err := publisheridentity.NewNative(control, authority, identity, private)
	if err != nil {
		return nil, err
	}
	if err := native.SelectPublicURL(publicURL); err != nil {
		return nil, err
	}
	if err := store.RecordPublisherEnrollmentResult(ctx, pending.EnrollmentID, pending.ResultJSON); err != nil {
		return nil, err
	}
	if err := store.PromotePublisherEnrollment(ctx, pending.EnrollmentID, clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: pending.ResultJSON, SigningKey: private}); err != nil {
		return nil, err
	}
	return native, nil
}
