package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisherruntime "github.com/tnldotdev/tnl/internal/publisher/runtime"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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

type relayCandidateControl interface {
	RelayCandidates(context.Context, string) (controlv1.RelayCandidates, error)
}

// Native is the single grant-scoped adapter for CLI, app, SDK, and guest
// entrypoints. construct one per selected URL/worker; it owns no local database.
type Native struct {
	NativeControl
	authority AssertionExchanger
	identity  nativeScope
	private   ed25519.PrivateKey
	publicURL controlv1.PublicURL
	traffic   *trafficlimits.Selection
	runtime   *publisherruntime.Owner
}

func NewNative(control NativeControl, authority AssertionExchanger, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (*Native, error) {
	if control == nil || authority == nil || !validSigningKey(private) {
		return nil, ErrScope
	}
	scope, err := newNativeScope(identity)
	if err != nil {
		return nil, err
	}
	return &Native{NativeControl: control, authority: authority, identity: scope, private: append(ed25519.PrivateKey(nil), private...)}, nil
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

// RelayCandidates reads deployment inventory without broadening this grant.
func (n *Native) RelayCandidates(ctx context.Context, access string) (controlv1.RelayCandidates, error) {
	control, ok := n.NativeControl.(relayCandidateControl)
	if !ok {
		return controlv1.RelayCandidates{}, ErrRegionUnsupported
	}
	if access == "" {
		var err error
		access, err = n.Access(ctx)
		if err != nil {
			return controlv1.RelayCandidates{}, err
		}
	}
	return control.RelayCandidates(ctx, access)
}

// ForGrant creates an independent worker adapter for another explicitly issued
// grant on this identity. token exchange verifies its live ownership on control.
func (n *Native) ForGrant(g controlv1.PublisherGrant) (*Native, error) {
	if n == nil || !opaqueid.Valid(g.Id, opaqueid.PublisherGrantPrefix) || g.RevokedAt != nil || g.ExpiresAt != nil && !g.ExpiresAt.After(time.Now()) || g.TeamId != nil && *g.TeamId != n.identity.teamID {
		return nil, ErrScope
	}
	i := n.identity.enrollment()
	i.GrantId, i.Kind, i.PublicUrlId, i.DomainId, i.Namespace = g.Id, authorityv1.PublisherEnrollmentResultKind(g.Kind), g.PublicUrlId, g.DomainId, g.Namespace
	i.ServiceId = g.ServiceId
	copy, err := NewNative(n.NativeControl, n.authority, i, n.private)
	if err != nil {
		return nil, err
	}
	return copy.WithTraffic(n.traffic)
}

func (n *Native) SelectPublicURL(publicURL controlv1.PublicURL) error {
	if n.identity.kind != authorityv1.SavedPublicUrl && n.identity.kind != authorityv1.Namespace {
		return ErrScope
	}
	if publicURL.TeamId != n.identity.teamID || publicURL.LifecycleState != controlv1.Enabled || !opaqueid.Valid(publicURL.Id, opaqueid.PublicURLPrefix) || n.publicURL.Id != "" && n.publicURL.Id != publicURL.Id {
		return ErrScope
	}
	if n.identity.kind == "saved_public_url" {
		if publicURL.Id != n.identity.publicURLID {
			return ErrScope
		}
	} else if !publicURL.Ephemeral || publicURL.ServiceProtocol != controlv1.Http || publicURL.DomainId != n.identity.domainID || !strings.HasSuffix(publicURL.CanonicalHostname, "."+n.identity.namespace) {
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

func (n *Native) Allocate(ctx context.Context, body controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error) {
	if n.identity.kind != "namespace" {
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

func (n *Native) CreatePublishRun(ctx context.Context, id, retry string) (controlv1.PublishRunSetup, error) {
	return n.CreatePublishRunInRegions(ctx, id, retry, nil)
}

func (n *Native) CreatePublishRunInRegions(ctx context.Context, id, retry string, preferred []string) (controlv1.PublishRunSetup, error) {
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
	if len(preferred) > 0 {
		control, ok := n.NativeControl.(interface {
			CreatePublisherRunWithOptions(context.Context, string, string, string, string, *trafficlimits.Selection, []string) (controlv1.PublishRunSetup, error)
		})
		if !ok {
			return controlv1.PublishRunSetup{}, ErrRegionUnsupported
		}
		return control.CreatePublisherRunWithOptions(ctx, id, retry, token, proof, n.traffic.Clone(), preferred)
	}
	if n.traffic != nil {
		control, ok := n.NativeControl.(TrafficControl)
		if !ok {
			return controlv1.PublishRunSetup{}, ErrTrafficUnsupported
		}
		return control.CreatePublisherRunWithTraffic(ctx, id, retry, token, proof, n.traffic.Clone())
	}
	return n.NativeControl.CreatePublisherRun(ctx, id, retry, token, proof)
}

func (n *Native) DeletePublicURL(ctx context.Context, id string) error {
	if n.identity.kind != "namespace" || n.publicURL.Id != id {
		return ErrScope
	}
	token, err := n.Access(ctx)
	if err != nil {
		return err
	}
	return n.NativeControl.DeletePublisherPublicURL(ctx, token, id)
}
