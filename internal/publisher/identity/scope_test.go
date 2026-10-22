package native

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// embedding preserves the full promoted control surface on pkg/tnl.Publisher.
var _ NativeControl = (*Native)(nil)

type snapshotURLControl struct {
	NativeControl
	url controlv1.PublicURL
}

func (c *snapshotURLControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return c.url, nil
}

func TestNativeScopeAndSelectedURLSnapshots(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	identity := fixture.identity.enrollment()
	id, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	identity.Kind, identity.PrivateServiceId, identity.PublicUrlId = authorityv1.SavedUrl, nil, &id
	prefixes := []string{"127.0.0.1/32"}
	membership, runID, pool, expires := "membership", "run", true, time.Now().Add(time.Hour)
	u := controlv1.PublicURL{Id: id, TeamId: identity.TeamId, CanonicalHostname: "app.example", LifecycleState: controlv1.Enabled, AllowedIpPrefixes: &prefixes, MembershipId: &membership, OpenPublishRunId: &runID, PublisherPool: &pool, ExpiresAt: &expires}
	expected := clonePublicURL(u)
	control := &snapshotURLControl{url: u}
	private := bytes.Clone(fixture.private)
	n, err := NewNative(control, &lostEnrollmentResponse{}, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	result, err := n.SavedURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// mutate every optional field of both the selected input and returned view.
	id = "changed-enrollment"
	(*result.AllowedIpPrefixes)[0] = "changed-prefix"
	*result.MembershipId, *result.OpenPublishRunId = "changed-member", "changed-run"
	*result.PublisherPool, *result.ExpiresAt = false, time.Time{}
	got, err := n.GetPublicURLByHostname(t.Context(), expected.TeamId, expected.CanonicalHostname)
	if err != nil || !reflect.DeepEqual(got, expected) || !bytes.Equal(n.private, fixture.private) {
		t.Fatal("caller mutation changed native scope, key, or selected URL", err)
	}
	*got.MembershipId = "changed-read"
	again, err := n.GetPublicURLByHostname(t.Context(), expected.TeamId, expected.CanonicalHostname)
	if err != nil || !reflect.DeepEqual(again, expected) {
		t.Fatal("read result aliased selected URL", err)
	}
	if err := n.SelectRoute(expected); err != nil {
		t.Fatal("enrollment pointer mutation changed exact URL authority", err)
	}
}

func TestNativeForkAndForGrantOwnIndependentScopes(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	i := fixture.identity.enrollment()
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	namespace := "member.example"
	i.Kind, i.PrivateServiceId, i.DomainId, i.Namespace = authorityv1.Namespace, nil, &domain, &namespace
	n, err := NewNative(&unusedControl{}, &lostEnrollmentResponse{}, i, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	newURL := func() controlv1.PublicURL {
		id, _ := opaqueid.New(opaqueid.PublicURLPrefix)
		return controlv1.PublicURL{Id: id, TeamId: i.TeamId, DomainId: domain, CanonicalHostname: "app." + namespace, LifecycleState: controlv1.Enabled, Ephemeral: true, ServiceProtocol: controlv1.Http}
	}
	first, second := newURL(), newURL()
	if err := n.SelectRoute(first); err != nil {
		t.Fatal(err)
	}
	fork, err := n.Fork()
	if err != nil {
		t.Fatal(err)
	}
	domain, namespace = "changed-domain", "changed.example"
	if err := fork.SelectRoute(second); err != nil {
		t.Fatal("fork retained the selected URL or aliased namespace authority", err)
	}
	if err := n.SelectRoute(second); !errors.Is(err, ErrScope) {
		t.Fatal("fork changed the original worker's selected URL", err)
	}
	grantID, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	selectedID := second.Id
	g := controlv1.PublisherGrant{Id: grantID, Kind: "saved_url", PublicUrlId: &selectedID}
	worker, err := n.ForGrant(g)
	if err != nil {
		t.Fatal(err)
	}
	selectedID = first.Id
	if err := worker.SelectRoute(second); err != nil {
		t.Fatal("ForGrant retained the prior selection or aliased its grant DTO", err)
	}
	if err := worker.NamespaceScope(); !errors.Is(err, ErrScope) {
		t.Fatal("saved URL worker retained namespace authority", err)
	}
	if err := n.NamespaceScope(); err != nil {
		t.Fatal("ForGrant changed original namespace authority", err)
	}
	clear(fork.private)
	if !bytes.Equal(n.private, fixture.private) || !bytes.Equal(worker.private, fixture.private) {
		t.Fatal("independent workers share signing-key storage")
	}
}
