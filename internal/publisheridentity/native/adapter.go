package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/publisherruntime"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrScope = errors.New("publisher operation is outside the selected grant")

type AssertionExchanger interface {
	ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error)
}

// NativeControl supplies the HTTP boundary without a dependency on the native
// publisher runtime. lifecycle operations keep using the publish run token.
type NativeControl interface {
	RunControl
	PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error)
	AllocatePublisherPublicURL(context.Context, string, controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error)
	DeletePublisherPublicURL(context.Context, string, string) error
	CreatePublisherRun(context.Context, string, string, string, string) (controlv1.PublishRunSetup, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken) error
	MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error
	HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.PublishRunToken, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error)
	MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.PublishRunToken) error
}

// Native is the single grant-scoped adapter for CLI, app, SDK, and guest
// entrypoints. construct one per selected URL/worker; it owns no local database.
type Native struct {
	NativeControl
	authority AssertionExchanger
	identity  authorityv1.PublisherEnrollmentResult
	private   ed25519.PrivateKey
	route     controlv1.PublicURL
	traffic   *trafficlimits.Selection
	runtime   *publisherruntime.Owner
}

func NewNative(control NativeControl, authority AssertionExchanger, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (*Native, error) {
	if control == nil || authority == nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) || !opaqueid.Valid(identity.ClientId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(identity.GrantId, opaqueid.PublisherGrantPrefix) || identity.TeamId == "" ||
		identity.Kind == "saved_url" && (identity.PublicUrlId == nil || !opaqueid.Valid(*identity.PublicUrlId, opaqueid.PublicURLPrefix) || identity.PrivateServiceId != nil || identity.Namespace != nil || identity.DomainId != nil) ||
		identity.Kind == "namespace" && (identity.Namespace == nil || identity.DomainId == nil || identity.PublicUrlId != nil || identity.PrivateServiceId != nil) ||
		identity.Kind == "private_service" && (identity.PrivateServiceId == nil || !opaqueid.Valid(*identity.PrivateServiceId, opaqueid.PrivateServicePrefix) || identity.PublicUrlId != nil || identity.Namespace != nil || identity.DomainId != nil) || !identity.Kind.Valid() {
		return nil, ErrScope
	}
	if identity.Kind == "namespace" {
		canonical, err := naming.CanonicalizeHostname(*identity.Namespace)
		if err != nil || canonical != *identity.Namespace || !opaqueid.Valid(*identity.DomainId, opaqueid.DomainPrefix) {
			return nil, ErrScope
		}
	}
	return &Native{NativeControl: control, authority: authority, identity: identity, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (n *Native) Access(ctx context.Context) (string, error) {
	return n.authority.ExchangePublisherAssertion(ctx, n.identity.ClientId, n.identity.GrantId, n.identity.KeyId, n.private)
}

func (n *Native) PublisherID() string {
	if n == nil {
		return ""
	}
	return n.identity.ClientId
}

// ForGrant creates an independent worker adapter for another explicitly issued
// grant on this identity. token exchange verifies its live ownership on control.
func (n *Native) ForGrant(g controlv1.PublisherGrant) (*Native, error) {
	if !opaqueid.Valid(g.Id, opaqueid.PublisherGrantPrefix) || g.RevokedAt != nil || g.ExpiresAt != nil && !g.ExpiresAt.After(time.Now()) {
		return nil, ErrScope
	}
	i := n.identity
	i.GrantId, i.Kind, i.PublicUrlId, i.DomainId, i.Namespace = g.Id, authorityv1.PublisherEnrollmentResultKind(g.Kind), g.PublicUrlId, g.DomainId, g.Namespace
	i.PrivateServiceId = g.PrivateServiceId
	copy, err := NewNative(n.NativeControl, n.authority, i, n.private)
	if err != nil {
		return nil, err
	}
	return copy.WithTraffic(n.traffic)
}

func (n *Native) SelectRoute(route controlv1.PublicURL) error {
	if n.identity.Kind != authorityv1.SavedUrl && n.identity.Kind != authorityv1.Namespace {
		return ErrScope
	}
	if route.TeamId != n.identity.TeamId || route.LifecycleState != controlv1.Enabled || !opaqueid.Valid(route.Id, opaqueid.PublicURLPrefix) || n.route.Id != "" && n.route.Id != route.Id {
		return ErrScope
	}
	if n.identity.Kind == "saved_url" {
		if route.Id != *n.identity.PublicUrlId {
			return ErrScope
		}
	} else if !route.Ephemeral || route.ServiceProtocol != controlv1.Http || route.DomainId != *n.identity.DomainId || !strings.HasSuffix(route.CanonicalHostname, "."+*n.identity.Namespace) {
		return ErrScope
	}
	n.route = route
	return nil
}

func (n *Native) SavedURL(ctx context.Context) (controlv1.PublicURL, error) {
	if n.identity.Kind != "saved_url" {
		return controlv1.PublicURL{}, ErrScope
	}
	token, err := n.Access(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	u, err := n.NativeControl.PublisherPublicURL(ctx, token)
	if err != nil {
		return u, err
	}
	return u, n.SelectRoute(u)
}

func (n *Native) Allocate(ctx context.Context, body controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error) {
	if n.identity.Kind != "namespace" {
		return controlv1.PublicURL{}, ErrScope
	}
	token, err := n.Access(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	u, err := n.NativeControl.AllocatePublisherPublicURL(ctx, token, body)
	if err != nil {
		return u, err
	}
	return u, n.SelectRoute(u)
}

func (n *Native) GetPublicURLByHostname(ctx context.Context, team, hostname string) (controlv1.PublicURL, error) {
	if n.route.Id == "" {
		if _, err := n.SavedURL(ctx); err != nil {
			return controlv1.PublicURL{}, err
		}
	}
	if n.route.TeamId != team || n.route.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, ErrScope
	}
	return n.route, nil
}

func (n *Native) CreatePublishRun(ctx context.Context, id, retry string) (controlv1.PublishRunSetup, error) {
	if n.route.Id == "" || n.route.Id != id {
		return controlv1.PublishRunSetup{}, ErrScope
	}
	// a deployed owner must still hold its accepted epoch before creating a
	// replacement run. a stale heartbeat must not loop into another signed run.
	if err := n.renewRuntime(ctx); err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	token, err := n.Access(ctx)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	proof, err := publisheridentity.SignRun(n.private, id, retry)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	if n.traffic != nil {
		control, ok := n.NativeControl.(TrafficControl)
		if !ok {
			return controlv1.PublishRunSetup{}, ErrTrafficUnsupported
		}
		return control.CreatePublisherRunWithTraffic(ctx, id, retry, token, proof, n.traffic)
	}
	return n.NativeControl.CreatePublisherRun(ctx, id, retry, token, proof)
}

func (*Native) CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, ErrScope
}
func (*Native) UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, ErrScope
}
func (n *Native) DeletePublicURL(ctx context.Context, id string) error {
	if n.identity.Kind != "namespace" || n.route.Id != id {
		return ErrScope
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	return n.NativeControl.DeletePublisherPublicURL(ctx, token, id)
}
