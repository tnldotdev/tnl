package controlstate

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestPublisherResolvedScopesHaveExclusiveTargets(t *testing.T) {
	for _, check := range []struct {
		resolved resolvedPublisherScope
		want     PublisherScope
	}{
		{savedURLPublisherScope{"team", "url"}, PublisherScope{TeamID: "team", Kind: "saved_url", PublicURLID: "url"}},
		{privateServicePublisherScope{"team", "private"}, PublisherScope{TeamID: "team", Kind: "private_service", PrivateServiceID: "private"}},
		{namespacePublisherScope{"team", "domain", "member.example", "member", PublicURLScopeMember}, PublisherScope{TeamID: "team", Kind: "namespace", DomainID: "domain", Namespace: "member.example", MembershipID: "member", PublicURLScope: PublicURLScopeMember}},
	} {
		if got := check.resolved.publisherScope(); !reflect.DeepEqual(got, check.want) {
			t.Fatalf("resolved target leaked another scope's fields: %+v", got)
		}
	}
	if _, err := insertPublisherGrant(t.Context(), nil, "publisher", "issuer", nil, nil, time.Time{}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("unresolved scope reached grant persistence", err)
	}
	for _, check := range []struct {
		row  controlstatedb.ControlAppliedProjectService
		kind string
	}{
		{controlstatedb.ControlAppliedProjectService{TeamID: "team", PublicURLID: text("url")}, "saved_url"},
		{controlstatedb.ControlAppliedProjectService{TeamID: "team", PrivateServiceID: text("private")}, "private_service"},
	} {
		scope := publisherScopeForAppliedService(check.row).publisherScope()
		if scope.TeamID != "team" || scope.Kind != check.kind || scope.Namespace != "" || scope.DomainID != "" || scope.MembershipID != "" {
			t.Fatalf("applied grant acquired caller namespace authority: %+v", scope)
		}
	}
}
