package main

import (
	"errors"
	"strings"
	"testing"

	clientidentity "github.com/tnldotdev/tnl/internal/client/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplicationRegistrationFlagsKeepOperationsAndExactResources(t *testing.T) {
	url, service, domain := "url_"+strings.Repeat("A", 22), "svc_"+strings.Repeat("B", 22), "dom_"+strings.Repeat("C", 22)
	spec, err := applicationRegistrationSpec(authRegisterCommand{Name: "worker", Ownership: "member", Visit: []string{url, service}, Publish: []string{url}, Allocate: []string{domain}}, "team")
	if err != nil || len(spec.Grants) != 4 || spec.Grants[0].Operation != controlv1.ApplicationVisit || spec.Grants[2].Operation != controlv1.ApplicationPublish || spec.Grants[3].Operation != controlv1.ApplicationAllocate {
		t.Fatal("registration inferred operations from resources", err)
	}
	for _, flags := range []authRegisterCommand{
		{Name: "worker", Ownership: "member"},
		{Name: "worker", Ownership: "member", Visit: []string{domain}},
		{Name: "worker", Ownership: "member", Allocate: []string{url}},
		{Name: "worker", Ownership: "member", Visit: []string{url, url}},
		{Name: "worker", Ownership: "member", Publish: []string{"https://app.example"}},
	} {
		if _, err := applicationRegistrationSpec(flags, "team"); !errors.Is(err, clientidentity.ErrRegistration) {
			t.Fatal("ambiguous registration flags were accepted", err)
		}
	}
}
