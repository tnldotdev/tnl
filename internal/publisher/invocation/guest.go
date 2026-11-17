package invocation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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
) (_ *clientstate.GuestSession, result error) {
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
	defer func() { result = errors.Join(result, lock.Close()) }()
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
			GuestID: issued.GuestId, AccessToken: issued.AccessToken,
			ExpiresAt: issued.ExpiresAt,
		}
		if err := store.SaveGuestSession(ctx, guest); err != nil {
			return nil, err
		}
	}
	return &guest, nil
}

// trial management owns allocation and deletion; the returned native identity
// can only publish its exact service. cleanup remains usable after an uncertain
// allocation error and never substitutes another request or extends trial time.
func prepareGuestDemoService(ctx context.Context, state *clientstate.Database, server string, guest clientstate.GuestSession, flags PublicOptions, target string) (*publisheridentity.Native, controlv1.Service, func() error, error) {
	if !opaqueid.Valid(guest.GuestID, opaqueid.GuestPrefix) || !guest.ExpiresAt.After(time.Now()) {
		return nil, controlv1.Service{}, nil, publisheridentity.ErrScope
	}
	ctx, cancel := context.WithDeadline(ctx, guest.ExpiresAt)
	defer cancel()
	location, err := targetsyntax.ParseCanonicalTarget(target)
	if err != nil {
		return nil, controlv1.Service{}, nil, err
	}
	address, err := netip.ParseAddr(location.Hostname())
	if err != nil || !address.IsLoopback() || location.Scheme != "http" {
		return nil, controlv1.Service{}, nil, publisheridentity.ErrScope
	}
	bootstrap, err := clientcontrol.New(server, nil, credentials.AccessToken(guest.AccessToken))
	if err != nil {
		return nil, controlv1.Service{}, nil, err
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return nil, controlv1.Service{}, nil, err
	}
	pq := flags.RequirePostQuantum != nil && *flags.RequirePostQuantum
	body := controlv1.AllocateGuestDemoServiceRequest{Target: target, RequirePostQuantum: &pq}
	allocation := &guestServiceAllocation{control: bootstrap, guest: clientstate.GuestSession{GuestID: guest.GuestID, ExpiresAt: guest.ExpiresAt}, request: body, key: key}
	cleanup := func() error {
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		return allocation.cleanup(finish)
	}
	saved, err := allocation.allocate(ctx)
	if err != nil {
		return nil, controlv1.Service{}, cleanup, err
	}
	profile, err := state.Server(ctx, server)
	if err != nil {
		return nil, saved, cleanup, err
	}
	native, err := enrollGuestNative(ctx, profile, saved, bootstrap)
	return native, saved, cleanup, err
}

type guestServiceControl interface {
	AllocateGuestDemoService(context.Context, string, controlv1.AllocateGuestDemoServiceRequest) (controlv1.Service, error)
	DeleteGuestService(context.Context, string) error
}

// this owner retains only trial identity, fixed time, and original allocation
// intent. the management client holds the credential; the native publisher does
// not receive it. failed deletion leaves the observed service available to retry.
type guestServiceAllocation struct {
	control   guestServiceControl
	guest     clientstate.GuestSession
	request   controlv1.AllocateGuestDemoServiceRequest
	key       string
	mu        sync.Mutex
	serviceID string
	deleted   bool
}

func (*guestServiceAllocation) String() string   { return "guest service allocation" }
func (*guestServiceAllocation) GoString() string { return "guest service allocation" }

func (a *guestServiceAllocation) allocate(ctx context.Context) (controlv1.Service, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.allocateLocked(ctx)
}

func (a *guestServiceAllocation) allocateLocked(ctx context.Context) (controlv1.Service, error) {
	if a.deleted || !a.guest.ExpiresAt.After(time.Now()) {
		return controlv1.Service{}, context.DeadlineExceeded
	}
	ctx, cancel := context.WithDeadline(ctx, a.guest.ExpiresAt)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return controlv1.Service{}, err
	}
	body := a.request
	if body.RequirePostQuantum != nil {
		body.RequirePostQuantum = new(*body.RequirePostQuantum)
	}
	saved, err := a.control.AllocateGuestDemoService(ctx, a.key, body)
	if cause := context.Cause(ctx); cause != nil {
		return controlv1.Service{}, errors.Join(err, cause)
	}
	if err != nil {
		return controlv1.Service{}, err
	}
	if err := validateGuestService(saved, a.guest, a.request); err != nil {
		return controlv1.Service{}, err
	}
	if a.serviceID != "" && saved.Id != a.serviceID {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	a.serviceID = saved.Id
	return saved, nil
}

func (a *guestServiceAllocation) cleanup(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.deleted {
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, a.guest.ExpiresAt)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if a.serviceID == "" {
		if _, err := a.allocateLocked(ctx); err != nil {
			return err
		}
	}
	err := a.control.DeleteGuestService(ctx, a.serviceID)
	if err == nil || errors.Is(err, clientcontrol.ErrNotFound) {
		a.deleted = true
		return nil
	}
	return err
}

func validateGuestService(saved controlv1.Service, guest clientstate.GuestSession, body controlv1.AllocateGuestDemoServiceRequest) error {
	pq := body.RequirePostQuantum != nil && *body.RequirePostQuantum
	if !opaqueid.Valid(saved.Id, opaqueid.ServicePrefix) || saved.GuestId != guest.GuestID || saved.TeamId != "" ||
		!saved.Enabled || !saved.Ephemeral || saved.PublisherPool || saved.Protocol != controlv1.ServiceProtocolHTTP ||
		saved.Endpoint == nil || !saved.Endpoint.Public || saved.Endpoint.Port != 443 ||
		saved.RequirePostQuantum != pq || saved.ExpiresAt == nil || !saved.ExpiresAt.After(time.Now()) || saved.ExpiresAt.After(guest.ExpiresAt) {
		return publisheridentity.ErrScope
	}
	return publisheridentity.MatchServiceDeclaration(saved, "http", nil)
}

// the trial credential only bootstraps one exact service. publication uses its
// own key and service grant, never the trial credential or a namespace grant.
func enrollGuestNative(ctx context.Context, store *clientstate.Store, saved controlv1.Service, bootstrap *clientcontrol.Client) (*publisheridentity.Native, error) {
	control, err := clientcontrol.New(bootstrap.ControlURL(), nil, "")
	if err != nil {
		return nil, err
	}
	authority, err := clientauthority.New(bootstrap.ControlURL(), nil, "")
	if err != nil {
		return nil, err
	}
	return enrollGuestNativeWithClients(ctx, store, saved, bootstrap, publisheridentity.NativeControl{Services: control, Runtime: control}, authority)
}

type guestEnrollmentClient interface {
	EnrollGuestPublisher(context.Context, string, ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error)
}

func enrollGuestNativeWithClients(ctx context.Context, store *clientstate.Store, saved controlv1.Service, bootstrap guestEnrollmentClient, control publisheridentity.NativeControl, authority publisheridentity.AssertionExchanger) (_ *publisheridentity.Native, result error) {
	if saved.Protocol != controlv1.ServiceProtocolHTTP || !saved.Enabled || !saved.Ephemeral || saved.ExpiresAt == nil || !saved.ExpiresAt.After(time.Now()) {
		return nil, publisheridentity.ErrScope
	}
	ctx, cancel := context.WithDeadline(ctx, *saved.ExpiresAt)
	defer cancel()
	scope := "guest-publisher:" + saved.Id
	lock, err := store.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	stored, found, err := store.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return nil, err
	}
	if found {
		native, receipt, err := publisheridentity.LoadNative(ctx, store, control, authority, stored.ID)
		if err != nil {
			return nil, err
		}
		if err := validateGuestEnrollment(receipt, saved); err != nil {
			return nil, err
		}
		selected, _, err := native.ForService(ctx, saved.Id)
		return selected, err
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
		pending = clientstate.PendingPublisherEnrollment{EnrollmentID: saved.Id, SelectionKind: "project", SelectionKey: scope, PublicKey: public, SigningKey: private, ExpiresAt: *saved.ExpiresAt}
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
		issued, err := bootstrap.EnrollGuestPublisher(ctx, saved.Id, private.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		if validateGuestEnrollment(issued, saved) != nil {
			return nil, failure.Wrap("enroll guest publisher", failure.ServerResponseInvalid, publisheridentity.ErrScope)
		}
		identity = issued
		pending.ResultJSON, err = json.Marshal(identity)
		if err != nil {
			return nil, err
		}
	}
	if err := validateGuestEnrollment(identity, saved); err != nil {
		return nil, err
	}
	native, err := publisheridentity.NewNative(control, authority, identity, private)
	if err != nil {
		return nil, err
	}
	native, _, err = native.ForService(ctx, saved.Id)
	if err != nil {
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

func validateGuestEnrollment(receipt authorityv1.PublisherEnrollmentResult, saved controlv1.Service) error {
	if saved.GuestId == "" || saved.TeamId != "" || saved.ExpiresAt == nil ||
		receipt.GuestId != saved.GuestId || receipt.TeamId != "" || receipt.Kind != authorityv1.Service ||
		receipt.ServiceId == nil || *receipt.ServiceId != saved.Id || receipt.ExpiresAt == nil ||
		!receipt.ExpiresAt.After(time.Now()) || receipt.ExpiresAt.After(*saved.ExpiresAt) {
		return publisheridentity.ErrScope
	}
	return nil
}
