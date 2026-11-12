package workload

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSourceChallengeUsesDefiningVisitorModelAndRetainedTuple(t *testing.T) {
	client, err := New("https://control.example", nil)
	if err != nil { t.Fatal(err) }
	source := authorityv1.IdentitySourceSelection{Kind: "registered_key", MachineId: "mci_0123456789ABCDEFGHIJKL", KeyId: "release/key-1"}
	selection := authorityv1.IdentitySourceVisitorSelection{Environment: environmentFixture(client.server), PermissionId: permissionFixture, Services: map[string]controlv1.ServiceProtocol{"db":"postgres"}}
	now := time.Now()
	first, err := client.SourceChallenge(source, selection, "owner-a", now)
	if err != nil { t.Fatal(err) }
	retry, err := client.SourceChallenge(source, selection, "owner-a", now.Add(time.Second))
	if err != nil { t.Fatal(err) }
	if first.Id == retry.Id || first.NativePublicKey != retry.NativePublicKey || first.Nonce != retry.Nonce || first.Scope != retry.Scope || first.BindingDigest != retry.BindingDigest || first.Source != source || first.Operation != "visitor_prepare" || first.Publication != nil || !reflect.DeepEqual(*first.Selection, selection) || !first.ExpiresAt.Equal(now.Add(time.Minute)) { t.Fatal("preparation challenge replaced its retained tuple or defining selection") }
	other, err := client.SourceChallenge(source, selection, "owner-b", now)
	if err != nil || other.BindingDigest == first.BindingDigest { t.Fatal("source challenge crossed native owners", err) }
	session := sessionFixture()
	session.LeaseExpiresAt = now.Add(20*time.Second)
	session.IdentityExpiresAt = now.Add(40*time.Second)
	client.session = session
	attach, err := client.SourceChallenge(source, selection, "owner-a", now)
	if err != nil { t.Fatal(err) }
	if attach.Operation != "visitor_attach" || attach.SessionId != session.Id || attach.Nonce != "" || attach.NativePublicKey != first.NativePublicKey || attach.BindingDigest == first.BindingDigest || !attach.ExpiresAt.Equal(session.LeaseExpiresAt) { t.Fatal("attachment challenge lost original session or applicable fence") }
	if machineproof.ValidateSourceChallenge(attach, now) != nil { t.Fatal("native emitted a noncanonical common challenge") }
	client.session.LeaseExpiresAt = now
	if _, err := client.SourceChallenge(source, selection, "owner-a", now); err == nil { t.Fatal("expired owner issued a fresh source challenge") }
}

func TestSourceChallengeRejectsInvalidSelectionAndSource(t *testing.T) {
	client, err := New("https://control.example", nil)
	if err != nil { t.Fatal(err) }
	source := authorityv1.IdentitySourceSelection{Kind: "oidc", MachineId: "mci_0123456789ABCDEFGHIJKL"}
	selection := authorityv1.IdentitySourceVisitorSelection{Environment: environmentFixture(client.server), PermissionId: permissionFixture, Services: map[string]controlv1.ServiceProtocol{"db":"postgres"}}
	for name, mutate := range map[string]func(*authorityv1.IdentitySourceSelection, *authorityv1.IdentitySourceVisitorSelection){
		"oidc key":func(s *authorityv1.IdentitySourceSelection, _ *authorityv1.IdentitySourceVisitorSelection){s.KeyId="not-allowed"},
		"missing registered key":func(s *authorityv1.IdentitySourceSelection, _ *authorityv1.IdentitySourceVisitorSelection){s.Kind="registered_key"},
		"control ref":func(_ *authorityv1.IdentitySourceSelection,s *authorityv1.IdentitySourceVisitorSelection){s.Environment.Server="https://other.example"},
		"environment id":func(_ *authorityv1.IdentitySourceSelection,s *authorityv1.IdentitySourceVisitorSelection){s.Environment.EnvironmentId="pgrp_"+strings.Repeat("a",22)},
		"protocol":func(_ *authorityv1.IdentitySourceSelection,s *authorityv1.IdentitySourceVisitorSelection){s.Services=map[string]controlv1.ServiceProtocol{"db":"ssh"}},
	} { t.Run(name,func(t *testing.T){s,v:=source,selection;mutate(&s,&v);if _,err:=client.SourceChallenge(s,v,"owner",time.Now());err==nil {t.Fatal("invalid source challenge accepted")}}) }
}
