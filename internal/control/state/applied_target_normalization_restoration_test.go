package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	publishertarget "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestAppliedTargetRestorationMatchesConfigAndRuntimeAfterConversion(t *testing.T) {
	for _, input := range []string{
		"http://localhost:3000", "https://EXAMPLE.test:443", "3000",
		"http://example.test", "https://example.test",
		"http://example.test:80/", "http://example.test:80#", "http://example.test:80?",
		"http://[2001:db8::1]:80", "http://user:secret@example.test:80", "http://example.test:0",
	} {
		t.Run(input, func(t *testing.T) {
			origin, configErr := config.NormalizeHTTPServiceTarget(config.Service{}, input)
			service := ProjectServiceConfiguration{Target: input, Public: new(true)}
			var trust *targettrust.Snapshot
			if strings.HasPrefix(input, "https://") {
				declaration, err := targettrust.NewDeclaration("upstream.internal", nil)
				if err != nil {
					t.Fatal(err)
				}
				service.TargetTLS = &ProjectTargetTLS{Hostname: declaration.Hostname, Digest: declaration.Digest}
				trust, err = declaration.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
			}
			runtime := publishertarget.TargetPlan{Protocol: config.ProtocolHTTP, Target: input, Trust: trust}
			runtimeErr := runtime.Normalize()
			if (configErr != nil) != (runtimeErr != nil) || configErr == nil && origin != runtime.Target {
				t.Fatal("config and runtime normalization disagree", origin, runtime.Target, configErr, runtimeErr)
			}
			if input == "3000" {
				// a bare port is config shorthand, not an applied dial address.
				// convert it with the existing owner before testing apply parity.
				if _, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": service}}); !errors.Is(err, ErrProjectConfigurationInvalid) {
					t.Fatal("raw port shorthand unexpectedly became an applied dial address", err)
				}
				if configErr != nil {
					t.Fatal("config rejected its port shorthand", configErr)
				}
				service.Target = origin
			}
			saved := service
			appliedErr := normalizeAppliedProjectService("web", &saved, savedServiceConfiguration)
			if (appliedErr != nil) != (runtimeErr != nil) {
				t.Fatal("applied origin and runtime acceptance disagree after scheme/trust conversion", appliedErr, runtimeErr)
			}
			if appliedErr != nil {
				return
			}
			var savedTrust *targettrust.Snapshot
			if saved.TargetTLS != nil {
				declaration := targettrust.Declaration{Hostname: saved.TargetTLS.Hostname, CAPEM: []byte(saved.TargetTLS.CAPEM), Digest: saved.TargetTLS.Digest}
				var err error
				savedTrust, err = declaration.Snapshot()
				if err != nil {
					t.Fatal("applied target lost validated trust", err)
				}
			}
			if (savedTrust == nil) != (trust == nil) || trust != nil && savedTrust.Digest != trust.Digest {
				t.Fatal("origin-to-dial conversion changed target trust")
			}
			converted := publishertarget.TargetPlan{Protocol: config.ProtocolHTTP, Target: saved.Target, Trust: savedTrust}
			if err := converted.Normalize(); err != nil {
				t.Fatal("applied dial address and trust did not convert to a runtime target", err)
			}
			convertedOrigin, err := config.NormalizeHTTPServiceTarget(config.Service{}, converted.Target)
			if err != nil || convertedOrigin != origin {
				t.Fatal("applied dial address and trust did not convert to the same canonical runtime origin", convertedOrigin, origin, err)
			}
			wantAddress, closeRuntime, err := publishertarget.ServiceTarget(t.Context(), runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer closeRuntime()
			gotAddress, closeApplied, err := publishertarget.ServiceTarget(t.Context(), converted)
			if err != nil {
				t.Fatal(err)
			}
			defer closeApplied()
			if gotAddress != wantAddress {
				t.Fatal("applied origin changed the runtime dial address", gotAddress, wantAddress)
			}
		})
	}
}
