package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var (
	_ resolvedPublisherScope = servicePublisherScope{}
	_ resolvedPublisherScope = namespacePublisherScope{}
	_ resolvedPublisherScope = deploymentCredentialScope{}
)

func TestPublisherResolvedScopesHaveExclusiveTargets(t *testing.T) {
	for _, check := range []struct {
		resolved resolvedPublisherScope
		want     PublisherScope
	}{
		{servicePublisherScope{teamID: "team", serviceID: "private"}, PublisherScope{TeamID: "team", Kind: "service", ServiceID: "private"}},
		{servicePublisherScope{guestID: "trial", serviceID: "demo"}, PublisherScope{GuestID: "trial", Kind: "service", ServiceID: "demo"}},
		{namespacePublisherScope{"team", "domain", "member.example", "member", NamespaceScopeMember}, PublisherScope{TeamID: "team", Kind: "namespace", DomainID: "domain", Namespace: "member.example", MembershipID: "member", NamespaceScope: NamespaceScopeMember}},
		{deploymentCredentialScope{team: "team"}, PublisherScope{TeamID: "team", Kind: DeploymentCredentialGrant}},
	} {
		if got := check.resolved.publisherScope(); !reflect.DeepEqual(got, check.want) {
			t.Fatalf("resolved target leaked another scope's fields: %+v", got)
		}
	}
	for _, root := range []resolvedPublisherScope{
		namespacePublisherScope{}, deploymentCredentialScope{team: "team"},
	} {
		if root.protocolCapability() != nil {
			t.Fatal("non-exact root acquired exact-service protocol capability")
		}
	}
	if _, err := insertPublisherGrant(t.Context(), nil, "publisher", "issuer", nil, nil, time.Time{}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("unresolved scope reached grant persistence", err)
	}
	scope := publisherScopeForAppliedService(controlstatedb.ControlAppliedProjectService{TeamID: "team", ServiceID: text("private")}, publisherProtocols{config.ProtocolTCP}).publisherScope()
	if scope.TeamID != "team" || scope.Kind != "service" || scope.ServiceID != "private" || scope.Namespace != "" || scope.DomainID != "" || scope.MembershipID != "" {
		t.Fatalf("applied grant acquired caller namespace authority: %+v", scope)
	}
}
