// Package publisherauth keeps control-facing publisher keys and grants inside
// the native publisher. local app credentials never cross this boundary.
package publisherauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrGrant = errors.New("publisher has no grant for this public URL")

type token struct {
	value string
	until time.Time
}

// Owner owns one signing key and independently revocable grants. an interactive
// owner creates its first identity automatically after selecting a saved URL.
type Owner struct {
	human        *clientauth.Client
	guestControl *controlclient.Client
	Control      *controlclient.Client
	Authority    *authorityclient.Client
	Name         string
	Kind         controlv1.CreatePublisherEnrollmentRequestKind

	mu            sync.Mutex
	private       ed25519.PrivateKey
	identity      authorityv1.PublisherEnrollmentResult
	grants        map[string]string
	namespaces    map[string]string
	accessByGrant map[string]token
	closed        bool
}

func Interactive(human *clientauth.Client, name string) (*Owner, error) {
	if human == nil || human.Control == nil || human.PublisherControl == nil || human.PublisherAuthority == nil {
		return nil, errors.New("publisher authentication needs a signed-in native owner")
	}
	return &Owner{human: human, Control: human.PublisherControl, Authority: human.PublisherAuthority,
		Name: name, Kind: controlv1.CreatePublisherEnrollmentRequestKindRun,
		grants: map[string]string{}, namespaces: map[string]string{}, accessByGrant: map[string]token{}}, nil
}

// Redeem registers a key generated on this machine. the one-use key is not
// retained after redemption; persistent owners will save the private key.
func Redeem(ctx context.Context, control *controlclient.Client, authority *authorityclient.Client, key string) (*Owner, error) {
	if control == nil || authority == nil || key == "" {
		return nil, errors.New("publisher enrollment needs control, authority, and a one-use key")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	identity, err := authority.RedeemPublisherEnrollment(ctx, key, public)
	if err != nil {
		return nil, err
	}
	owner := &Owner{Control: control, Authority: authority, private: private, identity: identity,
		grants: map[string]string{}, namespaces: map[string]string{}, accessByGrant: map[string]token{}}
	if identity.PublicUrlId != nil {
		owner.grants[*identity.PublicUrlId] = identity.GrantId
	} else if identity.Namespace != nil {
		owner.namespaces[identity.TeamId+"\x00"+*identity.Namespace] = identity.GrantId
	}
	return owner, nil
}

// Guest registers a key under one existing trial. its limited guest access
// token remains separate from publisher token exchange and run authentication.
func Guest(ctx context.Context, auth *clientauth.Client, trialToken credentials.AccessToken) (*Owner, error) {
	if auth == nil || auth.Control == nil || auth.PublisherControl == nil || auth.PublisherAuthority == nil {
		return nil, errors.New("guest demo needs a native publisher")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	registered, err := auth.PublisherControl.RegisterGuestPublisherIdentity(ctx, trialToken, public)
	if err != nil {
		return nil, err
	}
	if registered.ClientId == "" || registered.KeyId == "" || registered.GrantId == "" ||
		registered.TeamId == "" || registered.DomainId == "" || registered.Namespace == "" {
		return nil, errors.New("control returned an invalid guest publisher identity")
	}
	namespace := registered.Namespace
	identity := authorityv1.PublisherEnrollmentResult{ClientId: registered.ClientId, KeyId: registered.KeyId,
		GrantId: registered.GrantId, TeamId: registered.TeamId,
		Kind: authorityv1.PublisherEnrollmentResultKind("namespace"), Namespace: &namespace}
	identity.DomainId = &registered.DomainId
	owner := &Owner{Control: auth.PublisherControl, Authority: auth.PublisherAuthority,
		guestControl: auth.Control, private: private, identity: identity,
		grants: map[string]string{}, namespaces: map[string]string{}, accessByGrant: map[string]token{}}
	owner.namespaces[registered.TeamId+"\x00"+registered.Namespace] = registered.GrantId
	return owner, nil
}

func (o *Owner) grant(ctx context.Context, publicURLID string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "", ErrGrant
	}
	if grantID := o.grants[publicURLID]; grantID != "" {
		return grantID, nil
	}
	if o.human == nil {
		if o.identity.Kind == "namespace" {
			return o.identity.GrantId, nil
		}
		return "", ErrGrant
	}
	route, err := o.human.Control.GetPublicURL(ctx, publicURLID)
	if err != nil {
		return "", err
	}
	if o.identity.ClientId == "" {
		issued, err := o.human.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{
			TeamId: route.TeamId, PublicUrlId: &route.Id, Name: o.Name, Kind: o.Kind,
		})
		if err != nil {
			return "", err
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		identity, err := o.Authority.RedeemPublisherEnrollment(ctx, issued.EnrollmentKey, public)
		if err != nil {
			return "", err
		}
		if identity.PublicUrlId == nil || *identity.PublicUrlId != publicURLID || identity.TeamId != route.TeamId {
			return "", errors.New("control returned a different publisher grant")
		}
		o.identity, o.private = identity, private
		o.grants[publicURLID] = identity.GrantId
		return identity.GrantId, nil
	}
	if route.TeamId != o.identity.TeamId {
		return "", ErrGrant
	}
	added, err := o.human.Control.CreatePublisherGrant(ctx, o.identity.ClientId, controlv1.CreatePublisherGrantRequest{
		TeamId: controlv1.TeamID(route.TeamId), PublicUrlId: &route.Id,
	})
	if err != nil {
		return "", err
	}
	if added.PublicUrlId == nil || *added.PublicUrlId != publicURLID || added.TeamId != route.TeamId || added.Id == "" {
		return "", errors.New("control returned a different publisher grant")
	}
	o.grants[publicURLID] = added.Id
	return added.Id, nil
}

func (o *Owner) access(ctx context.Context, grantID string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "", ErrGrant
	}
	if cached := o.accessByGrant[grantID]; cached.value != "" && cached.until.After(time.Now().Add(30*time.Second)) {
		return cached.value, nil
	}
	value, until, err := o.Authority.ExchangePublisherAssertion(ctx, o.identity.ClientId, grantID, o.identity.KeyId, o.private)
	if err != nil {
		return "", err
	}
	o.accessByGrant[grantID] = token{value: value, until: until}
	return value, nil
}

func (o *Owner) CreateRun(ctx context.Context, publicURLID, idempotencyKey string, traffic ...trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	grantID, err := o.grant(ctx, publicURLID)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	access, err := o.access(ctx, grantID)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	proof, err := publisheridentity.SignRun(o.private, publicURLID, idempotencyKey)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	return o.Control.CreatePublishRunWithPublisherAccess(ctx, publicURLID, idempotencyKey, access, proof, traffic...)
}

func (o *Owner) BoundURL(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	if o.human != nil {
		return o.human.Control.GetPublicURLByHostname(ctx, teamID, hostname)
	}
	if o.guestControl != nil {
		return o.guestControl.GetPublicURLByHostname(ctx, teamID, hostname)
	}
	route, err := o.CurrentURL(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	if route.TeamId != teamID || route.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, ErrGrant
	}
	return route, nil
}

func (o *Owner) CurrentURL(ctx context.Context) (controlv1.PublicURL, error) {
	if o.identity.PublicUrlId == nil {
		return controlv1.PublicURL{}, ErrGrant
	}
	access, err := o.access(ctx, o.identity.GrantId)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	route, err := o.Control.PublisherPublicURL(ctx, access)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	if route.Id != *o.identity.PublicUrlId || route.TeamId != o.identity.TeamId {
		return controlv1.PublicURL{}, ErrGrant
	}
	return route, nil
}

// Close revokes an interactive owner's run-scoped identity. installed and
// guest identities keep their independent enrollment or trial lifecycle.
func (o *Owner) Close(ctx context.Context) error {
	if o == nil || o.human == nil || o.Kind != controlv1.CreatePublisherEnrollmentRequestKindRun {
		return nil
	}
	o.mu.Lock()
	if o.closed || o.identity.ClientId == "" {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	id, teamID := o.identity.ClientId, o.identity.TeamId
	o.mu.Unlock()
	if err := o.human.Control.RevokePublisherIdentity(ctx, teamID, id); err != nil {
		o.mu.Lock()
		o.closed = false
		o.mu.Unlock()
		return err
	}
	return nil
}
