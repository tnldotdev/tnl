package publisherauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// Namespace is the explicit team and DNS boundary selected by the native
// project owner. app SDKs do not supply a publisher key or grant.
type Namespace struct {
	TeamID, DomainID, Hostname string
	Scope                      controlv1.PublicURLScope
}

func (n Namespace) key() string { return n.TeamID + "\x00" + n.Hostname }

func (o *Owner) NamespaceGrant(ctx context.Context, namespace Namespace) (string, error) {
	if namespace.TeamID == "" || namespace.DomainID == "" || namespace.Hostname == "" || o.human != nil && !namespace.Scope.Valid() {
		return "", ErrGrant
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "", ErrGrant
	}
	if grantID := o.namespaces[namespace.key()]; grantID != "" {
		return grantID, nil
	}
	if o.human == nil {
		return "", ErrGrant
	}
	domainID := controlv1.DomainID(namespace.DomainID)
	if o.identity.ClientId == "" {
		issued, err := o.human.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{
			TeamId: controlv1.TeamID(namespace.TeamID), DomainId: &domainID,
			PublicUrlScope: &namespace.Scope, Name: o.Name, Kind: o.Kind,
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
		if identity.Kind != "namespace" || identity.Namespace == nil || *identity.Namespace != namespace.Hostname ||
			identity.TeamId != namespace.TeamID {
			return "", errors.New("control returned a different publisher namespace grant")
		}
		o.identity, o.private = identity, private
		o.namespaces[namespace.key()] = identity.GrantId
		return identity.GrantId, nil
	}
	if o.identity.TeamId != namespace.TeamID {
		return "", ErrGrant
	}
	added, err := o.human.Control.CreatePublisherGrant(ctx, o.identity.ClientId, controlv1.CreatePublisherGrantRequest{
		TeamId: controlv1.TeamID(namespace.TeamID), DomainId: &domainID, PublicUrlScope: &namespace.Scope,
	})
	if err != nil {
		return "", err
	}
	if added.Kind != "namespace" || added.Namespace == nil || *added.Namespace != namespace.Hostname ||
		added.TeamId != namespace.TeamID || added.Id == "" {
		return "", errors.New("control returned a different publisher namespace grant")
	}
	o.namespaces[namespace.key()] = added.Id
	return added.Id, nil
}

// EnrolledNamespace returns the exact namespace issued with a one-use key.
func (o *Owner) EnrolledNamespace() (Namespace, bool) {
	if o.identity.Kind != "namespace" || o.identity.Namespace == nil || o.identity.DomainId == nil {
		return Namespace{}, false
	}
	return Namespace{TeamID: o.identity.TeamId, DomainID: *o.identity.DomainId, Hostname: *o.identity.Namespace}, true
}

func (o *Owner) Allocate(ctx context.Context, namespace Namespace, body controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, string, error) {
	grantID, err := o.NamespaceGrant(ctx, namespace)
	if err != nil {
		return controlv1.PublicURL{}, "", err
	}
	token, err := o.access(ctx, grantID)
	if err != nil {
		return controlv1.PublicURL{}, "", err
	}
	route, err := o.Control.AllocatePublisherPublicURL(ctx, token, body)
	if err != nil {
		return controlv1.PublicURL{}, "", err
	}
	if route.TeamId != namespace.TeamID || route.DomainId != namespace.DomainID ||
		!strings.HasSuffix(route.CanonicalHostname, "."+namespace.Hostname) || !route.Ephemeral {
		return controlv1.PublicURL{}, "", errors.New("control returned an allocation outside the publisher namespace")
	}
	return route, grantID, nil
}

func (o *Owner) CreateNamespaceRun(ctx context.Context, publicURLID, grantID, key string, traffic ...trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	o.mu.Lock()
	allowed := false
	for _, scoped := range o.namespaces {
		if scoped == grantID {
			allowed = true
			break
		}
	}
	o.mu.Unlock()
	if !allowed {
		return controlv1.PublishRunSetup{}, ErrGrant
	}
	access, err := o.access(ctx, grantID)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	proof, err := publisheridentity.SignRun(o.private, publicURLID, key)
	if err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	return o.Control.CreatePublishRunWithPublisherAccess(ctx, publicURLID, key, access, proof, traffic...)
}

func (o *Owner) DeleteNamespaceURL(ctx context.Context, grantID, publicURLID string) error {
	token, err := o.access(ctx, grantID)
	if err != nil {
		return err
	}
	return o.Control.DeletePublisherPublicURL(ctx, token, publicURLID)
}
