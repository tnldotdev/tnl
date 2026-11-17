package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestServiceAllocationInlineHandler(t *testing.T) {
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	configuration := ProjectServiceConfiguration{
		Target: "app",
		HTTP:   &config.HTTPService{Access: &config.Access{Mode: "anonymous"}},
	}
	saved, mode, err := normalizeServiceAllocation(AllocateServiceRequest{
		Invocation: invocation, Configuration: configuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Target != "app" || saved.Protocol != "http" || saved.Name != "temporary" ||
		!saved.Ephemeral || saved.Public == nil || !*saved.Public || mode != "anonymous" {
		t.Fatal("inline allocation lost its declaration or access setting")
	}
	if configuration.Protocol != "" || configuration.Name != "" || configuration.Public != nil ||
		configuration.Ephemeral {
		t.Fatal("normalization mutated the caller's declaration")
	}
}

func TestServiceAllocationInlineHandlerBoundaries(t *testing.T) {
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		configuration ProjectServiceConfiguration
		invocation    string
	}{
		{"compose", ProjectServiceConfiguration{Target: "compose:web:3000"}, invocation},
		{"docker", ProjectServiceConfiguration{Target: "docker:web:3000"}, invocation},
		{"non-http", ProjectServiceConfiguration{Target: "app", Protocol: "tcp"}, invocation},
		{"target-tls", ProjectServiceConfiguration{Target: "app", TargetTLS: &ProjectTargetTLS{Hostname: "target.test"}}, invocation},
		{"private", ProjectServiceConfiguration{Target: "app", Public: new(false)}, invocation},
		{"hostname", ProjectServiceConfiguration{Target: "app", Hostname: "other.test"}, invocation},
		{"readiness", ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/"}}}, invocation},
		{"invalid-invocation", ProjectServiceConfiguration{Target: "app"}, "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := normalizeServiceAllocation(AllocateServiceRequest{
				Invocation: test.invocation, Configuration: test.configuration,
			})
			if !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("allocation accepted an unsupported inline declaration", err)
			}
		})
	}
}
