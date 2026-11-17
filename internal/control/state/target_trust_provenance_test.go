package state

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestTargetTrustProvenanceIsValidatedAndConfigurationFenced(t *testing.T) {
	custom := appliedTargetTrust(t, "target.example")
	for _, test := range []struct {
		name, target, hostname string
		ca                     string
		automatic              bool
		invalid                bool
	}{
		{name: "origin-derived", target: "https://target.example", hostname: "target.example", automatic: true},
		{name: "canonical hostname", target: "https://TARGET.example", hostname: "target.example", automatic: true},
		{name: "pinned same name", target: "https://target.example", hostname: "target.example"},
		{name: "pinned override", target: "https://target.example", hostname: "pinned.example"},
		{name: "app captured identity", target: "app", hostname: "target.example", automatic: true},
		{name: "wrong automatic host", target: "https://target.example", hostname: "pinned.example", automatic: true, invalid: true},
		{name: "DNS is not an IP identity", target: "https://127.0.0.1", hostname: "localhost", automatic: true, invalid: true},
		{name: "IP is not a DNS identity", target: "https://localhost", hostname: "127.0.0.1", automatic: true, invalid: true},
		{name: "different IP identities", target: "https://127.0.0.1", hostname: "::ffff:127.0.0.2", automatic: true, invalid: true},
		{name: "custom cannot be automatic", target: "https://target.example", hostname: "target.example", ca: custom.CAPEM, automatic: true, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := &ProjectServiceConfiguration{Target: test.target,
				TargetTLS: &ProjectTargetTLS{Hostname: test.hostname, CAPEM: test.ca, HostnameFromTarget: test.automatic}}
			saved, err := normalizeServiceConfiguration("web", configuration)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid hostname provenance was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if saved.TargetTLS.HostnameFromTarget != test.automatic || saved.TargetTLS.Digest == "" {
				t.Fatal("normalization lost provenance or trust approval", saved.TargetTLS)
			}
			if !test.automatic {
				return
			}
			automaticDigest, err := serviceConfigurationDigest(saved)
			if err != nil {
				t.Fatal(err)
			}
			automaticTrust, err := appliedServiceTargetTrust(saved.TargetTLS)
			if err != nil {
				t.Fatal(err)
			}
			saved.TargetTLS.HostnameFromTarget = false
			pinnedDigest, err := serviceConfigurationDigest(saved)
			if err != nil {
				t.Fatal(err)
			}
			pinnedTrust, err := appliedServiceTargetTrust(saved.TargetTLS)
			if err != nil {
				t.Fatal(err)
			}
			if automaticDigest == pinnedDigest || automaticTrust.Digest != pinnedTrust.Digest {
				t.Fatal("provenance must change the configuration fence, not runtime trust")
			}
		})
	}
}

func TestTargetTrustProvenancePreservesIPIdentityAcrossAddressNormalization(t *testing.T) {
	ca := appliedTargetTrust(t, "target.example").CAPEM
	for _, host := range []string{"127.0.0.1", "2001:db8::1", "::ffff:127.0.0.1"} {
		for _, mode := range []string{"automatic", "pinned system", "pinned custom"} {
			t.Run(host+" "+mode, func(t *testing.T) {
				address := net.JoinHostPort(host, "8443")
				hostname, roots := "", "system"
				if mode == "pinned system" {
					hostname = host
				} else if mode == "pinned custom" {
					roots = ca
				}
				captured, err := targettrust.CapturePortable(t.Context(), "http", address, roots, hostname)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := captured.Verifier()
				if err != nil || verifier.ServerName != captured.Hostname {
					t.Fatal("captured identity is not verifiable", verifier, err)
				}
				declaration, err := captured.Declaration()
				if err != nil {
					t.Fatal(err)
				}
				tls := &ProjectTargetTLS{Hostname: declaration.Hostname, CAPEM: string(declaration.CAPEM),
					Digest: declaration.Digest, HostnameFromTarget: declaration.HostnameFromTarget}
				input := &ProjectServiceConfiguration{Target: "https://" + address, TargetTLS: tls}
				saved, err := normalizeServiceConfiguration("web", input)
				if err != nil {
					t.Fatal("captured IP trust did not survive address normalization", err)
				}
				wantTarget := net.JoinHostPort(netip.MustParseAddr(host).Unmap().String(), "8443")
				if saved.Target != wantTarget || !reflect.DeepEqual(saved.TargetTLS, tls) ||
					saved.TargetTLS.HostnameFromTarget != (mode == "automatic") {
					t.Fatal("dial address normalization changed approved trust or intent", saved, tls)
				}
				trust, err := appliedServiceTargetTrust(saved.TargetTLS)
				if err != nil || trust.Hostname != captured.Hostname || trust.Digest != captured.Digest || trust.PEM != string(captured.PEM) {
					t.Fatal("normalized configuration changed approved TLS material", trust, err)
				}
				again, err := normalizeServiceConfiguration("web", saved)
				if err != nil || !reflect.DeepEqual(again, saved) {
					t.Fatal("normalized IP target does not round-trip with its captured trust", again, err)
				}
				// a normalized dial address must not replace an explicit TLS identity.
				recaptured, err := targettrust.CapturePortable(t.Context(), "http", saved.Target, roots, captured.Hostname)
				if err != nil || recaptured.Hostname != captured.Hostname || recaptured.Digest != captured.Digest {
					t.Fatal("normalized target replaced an explicit approved TLS identity", recaptured, err)
				}
			})
		}
	}
}

func TestDeploymentTargetRoundTripRetainsDefaultAndExplicitHostname(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "origin-derived", true: "explicit same name"}[explicit], func(t *testing.T) {
			input := DeploymentTarget{Address: "https://target.example:443", TLS: &DeploymentTargetTLS{CA: "system"}}
			if explicit {
				input.TLS.Hostname = "target.example"
			}
			saved, err := normalizeDeploymentTarget(t.Context(), "web", "http", input)
			if err != nil {
				t.Fatal(err)
			}
			status := deploymentTarget(saved)
			if saved.TargetTLS.HostnameFromTarget != !explicit || status.TLS.Hostname != input.TLS.Hostname {
				t.Fatal("deployment target status turned a default into an explicit hostname", saved.TargetTLS, status)
			}
			again, err := normalizeDeploymentTarget(t.Context(), "web", "http", DeploymentTarget{Address: status.Address, TLS: status.TLS})
			if err != nil || again.TargetTLS.HostnameFromTarget != !explicit {
				t.Fatal("deployment target round trip lost hostname provenance", again, err)
			}
			material, err := targettrust.NewDeclaration("target.example", nil)
			if err != nil || saved.TargetTLS.Digest != material.Digest {
				t.Fatal("provenance changed the approved trust material", err)
			}
		})
	}
}
