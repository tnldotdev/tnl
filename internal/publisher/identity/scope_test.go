package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// embedding preserves the full promoted control surface on pkg/tnl.Publisher.
var _ PublicURLControl = (*Native)(nil)

func (s nativeScope) enrollment() authorityv1.PublisherEnrollmentResult {
	i := authorityv1.PublisherEnrollmentResult{ClientId: s.clientID, KeyId: s.keyID, GrantId: s.grantID, TeamId: s.teamID, Kind: authorityv1.PublisherEnrollmentResultKind(s.kind)}
	switch s.kind {
	case "saved_public_url":
		i.PublicUrlId = &s.publicURLID
	case "service":
		i.ServiceId = &s.serviceID
	case "namespace":
		i.DomainId, i.Namespace = &s.domainID, &s.namespace
	}
	return i
}

type snapshotURLControl struct {
	unusedControl
	url controlv1.PublicURL
}

type endpointControl struct {
	PublicURLControl
	server string
}

func (c endpointControl) ControlURL() string { return c.server }

func TestNativeRequiresEndpointIdentityAndSelectedCapabilities(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	service := fixture.identity.enrollment()
	url := service
	id, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	url.Kind, url.ServiceId, url.PublicUrlId = authorityv1.SavedPublicUrl, nil, &id
	for _, server := range []string{"", "https://control.example/path", "https://CONTROL.example/"} {
		if _, err := NewNative(NativeControl{PublicURLControl: endpointControl{server: server}}, &lostEnrollmentResponse{}, url, fixture.private); !errors.Is(err, ErrScope) {
			t.Fatalf("invalid endpoint identity %q accepted: %v", server, err)
		}
	}
	control := NativeControl{PublicURLControl: &unusedControl{}}
	if _, err := NewNative(control, &lostEnrollmentResponse{}, service, fixture.private); !errors.Is(err, ErrScope) {
		t.Fatal("service grant accepted without service capabilities", err)
	}
	if _, err := NewNative(control, &lostEnrollmentResponse{}, url, fixture.private); err != nil {
		t.Fatal("URL-only grant required irrelevant service capabilities", err)
	}
	// endpoint validation does not weaken signing-key validation.
	if _, err := NewNative(control, &lostEnrollmentResponse{}, url, make(ed25519.PrivateKey, ed25519.PrivateKeySize)); !errors.Is(err, ErrScope) {
		t.Fatal("invalid signing key accepted", err)
	}
}

func (c *snapshotURLControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return c.url, nil
}

func TestNativeScopeAndSelectedURLSnapshots(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	identity := fixture.identity.enrollment()
	id, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	identity.Kind, identity.ServiceId, identity.PublicUrlId = authorityv1.SavedPublicUrl, nil, &id
	prefixes := []string{"127.0.0.1/32"}
	membership, runID, pool, expires := "membership", "run", true, time.Now().Add(time.Hour)
	u := controlv1.PublicURL{Id: id, TeamId: identity.TeamId, CanonicalHostname: "app.example", LifecycleState: controlv1.Enabled, AllowedIpPrefixes: &prefixes, MembershipId: &membership, OpenPublishRunId: &runID, PublisherPool: &pool, ExpiresAt: &expires}
	expected := clonePublicURL(u)
	control := &snapshotURLControl{url: u}
	private := bytes.Clone(fixture.private)
	n, err := NewNative(NativeControl{PublicURLControl: control}, &lostEnrollmentResponse{}, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	result, err := n.SavedPublicURL(t.Context())
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
	if err := n.SelectPublicURL(expected); err != nil {
		t.Fatal("enrollment pointer mutation changed exact URL authority", err)
	}
}

func TestNativeForkAndForGrantOwnIndependentScopes(t *testing.T) {
	fixture, control := privateScopeFixture(t)
	i := fixture.identity.enrollment()
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	namespace := "member.example"
	i.Kind, i.ServiceId, i.DomainId, i.Namespace = authorityv1.Namespace, nil, &domain, &namespace
	n, err := NewNative(NativeControl{PublicURLControl: &unusedControl{}, Services: control}, &lostEnrollmentResponse{}, i, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	newURL := func() controlv1.PublicURL {
		id, _ := opaqueid.New(opaqueid.PublicURLPrefix)
		return controlv1.PublicURL{Id: id, TeamId: i.TeamId, DomainId: domain, CanonicalHostname: "app." + namespace, LifecycleState: controlv1.Enabled, Ephemeral: true, ServiceProtocol: controlv1.Http}
	}
	first, second := newURL(), newURL()
	if err := n.SelectPublicURL(first); !errors.Is(err, ErrScope) {
		t.Fatal("namespace grant retained the separate URL allocation engine", err)
	}
	selected, _, err := n.ForService(t.Context(), control.service.Id)
	if err != nil {
		t.Fatal(err)
	}
	fork, err := n.Fork()
	if err != nil {
		t.Fatal(err)
	}
	domain, namespace = "changed-domain", "changed.example"
	sibling, _ := opaqueid.New(opaqueid.ServicePrefix)
	control.service.Id = sibling
	if _, _, err := fork.ForService(t.Context(), sibling); err != nil {
		t.Fatal("independent namespace worker could not select its allocated service", err)
	}
	if _, _, err := selected.ForService(t.Context(), sibling); !errors.Is(err, ErrScope) {
		t.Fatal("fork changed the original worker's selected service", err)
	}
	grantID, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	selectedID := second.Id
	g := controlv1.PublisherGrant{Id: grantID, Kind: "saved_public_url", PublicUrlId: &selectedID}
	worker, err := n.ForGrant(g)
	if err != nil {
		t.Fatal(err)
	}
	selectedID = first.Id
	if err := worker.SelectPublicURL(second); err != nil {
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
