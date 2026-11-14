package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrScope = errors.New("publisher operation is outside the selected grant")

type AssertionExchanger interface {
	ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error)
}

// PublicURLControl supplies the HTTP boundary without a dependency on the native
// publisher runtime. lifecycle operations keep using the publish run token.
type PublicURLControl interface {
	RunControl
	PublisherAuditControl
	ControlURL() string
	PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error)
	// nil traffic selection uses control's defaults.
	CreatePublisherRun(context.Context, string, string, string, string, *trafficlimits.Selection, ...string) (controlv1.PublishRunSetup, error)
	ClosePublishRun(context.Context, string, credentials.PublishRunToken) error
	MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error
	HeartbeatPublishRun(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error)
	CreateCertificateIssuance(context.Context, string, uint64, credentials.PublishRunToken, []byte, string) (controlv1.CertificateIssuance, error)
	GetCertificateIssuance(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error)
	MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.PublishRunToken) error
}

// NativeControl supplies explicit capabilities for the selected operation.
// public URL callers leave Services nil; deployed owners supply Runtime.
type NativeControl struct {
	PublicURLControl
	Services    ServiceControl
	Allocations ServiceAllocationControl
	Runtime     processidentity.Control
}

// Native is the single grant-scoped adapter for CLI, app, SDK, and guest
// entrypoints. construct one per selected URL/worker; it owns no local database.
type Native struct {
	NativeControl
	authority            AssertionExchanger
	identity             nativeScope
	selectedServiceID    string
	allocationInvocation string
	allocatedServiceID   string
	private              ed25519.PrivateKey
	publicURL            controlv1.PublicURL
	traffic              *trafficlimits.Selection
	runtime              *processidentity.Owner
}

func NewNative(control NativeControl, authority AssertionExchanger, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (*Native, error) {
	scope, err := newNativeScope(identity)
	if err != nil {
		return nil, err
	}
	return newNative(control, authority, scope, private)
}

func newNative(control NativeControl, authority AssertionExchanger, scope nativeScope, private ed25519.PrivateKey) (*Native, error) {
	if authority == nil || !validSigningKey(private) || control.Services == nil && control.PublicURLControl == nil {
		return nil, ErrScope
	}
	n := &Native{NativeControl: control, authority: authority, identity: scope, selectedServiceID: scope.serviceID, private: append(ed25519.PrivateKey(nil), private...)}
	server, err := naming.CanonicalControlURL(n.ControlURL())
	if err != nil || server != n.ControlURL() ||
		(scope.kind == "service" || scope.kind == "deployment_credential") && control.Services == nil ||
		scope.kind == "saved_public_url" && control.PublicURLControl == nil {
		return nil, ErrScope
	}
	if control.PublicURLControl != nil && control.PublicURLControl.ControlURL() != server {
		return nil, ErrScope
	}
	return n, nil
}

func validSigningKey(private ed25519.PrivateKey) bool {
	return len(private) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private)
}

func (n *Native) Access(ctx context.Context) (string, error) {
	return n.authority.ExchangePublisherAssertion(ctx, n.identity.clientID, n.identity.grantID, n.identity.keyID, append(ed25519.PrivateKey(nil), n.private...))
}

func (n *Native) PublisherIdentityID() string {
	if n == nil {
		return ""
	}
	return n.identity.clientID
}

func (n *Native) PublisherGrantID() string { return n.identity.grantID }
func (n *Native) PublisherKeyID() string   { return n.identity.keyID }

// ForGrant creates an independent worker adapter for another explicitly issued
// grant on this identity. token exchange verifies its live ownership on control.
func (n *Native) ForGrant(g controlv1.PublisherGrant) (*Native, error) {
	if n == nil || !opaqueid.Valid(g.Id, opaqueid.PublisherGrantPrefix) || g.RevokedAt != nil || g.ExpiresAt != nil && !g.ExpiresAt.After(time.Now()) || g.TeamId != nil && *g.TeamId != n.identity.teamID {
		return nil, ErrScope
	}
	if g.Kind == "deployment_credential" {
		if g.ServiceId != nil || g.PublicUrlId != nil || g.DomainId != nil || g.Namespace != nil {
			return nil, ErrScope
		}
		scope := nativeScope{clientID: n.identity.clientID, keyID: n.identity.keyID, grantID: g.Id, teamID: n.identity.teamID, kind: string(g.Kind)}
		copy, err := newNative(n.NativeControl, n.authority, scope, n.private)
		if err != nil {
			return nil, err
		}
		return copy.WithTraffic(n.traffic)
	}
	i := authorityv1.PublisherEnrollmentResult{ClientId: n.identity.clientID, KeyId: n.identity.keyID, TeamId: n.identity.teamID}
	i.GrantId, i.Kind, i.PublicUrlId, i.DomainId, i.Namespace = g.Id, authorityv1.PublisherEnrollmentResultKind(g.Kind), g.PublicUrlId, g.DomainId, g.Namespace
	i.ServiceId = g.ServiceId
	copy, err := NewNative(n.NativeControl, n.authority, i, n.private)
	if err != nil {
		return nil, err
	}
	return copy.WithTraffic(n.traffic)
}

func (n *Native) SelectPublicURL(publicURL controlv1.PublicURL) error {
	if n.identity.kind != "saved_public_url" {
		return ErrScope
	}
	if publicURL.TeamId != n.identity.teamID || publicURL.LifecycleState != controlv1.Enabled || !opaqueid.Valid(publicURL.Id, opaqueid.PublicURLPrefix) || n.publicURL.Id != "" && n.publicURL.Id != publicURL.Id {
		return ErrScope
	}
	if publicURL.Id != n.identity.publicURLID {
		return ErrScope
	}
	n.publicURL = clonePublicURL(publicURL)
	return nil
}

func (n *Native) SavedPublicURL(ctx context.Context) (controlv1.PublicURL, error) {
	if n.identity.kind != "saved_public_url" {
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
	return u, n.SelectPublicURL(u)
}

func (n *Native) GetPublicURLByHostname(ctx context.Context, team, hostname string) (controlv1.PublicURL, error) {
	if n.publicURL.Id == "" {
		if _, err := n.SavedPublicURL(ctx); err != nil {
			return controlv1.PublicURL{}, err
		}
	}
	if n.publicURL.TeamId != team || n.publicURL.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, ErrScope
	}
	return clonePublicURL(n.publicURL), nil
}

func (n *Native) CreatePublishRun(ctx context.Context, id, retry string, preferred ...string) (controlv1.PublishRunSetup, error) {
	if n.publicURL.Id == "" || n.publicURL.Id != id {
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
	proof, err := publisherproof.SignRun(n.private, id, retry)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	return n.NativeControl.CreatePublisherRun(ctx, id, retry, token, proof, n.traffic.Clone(), preferred...)
}
